package Amin::Example::Shop;
use v5.38; use warnings; use utf8;
use Class::Tiny qw(Handler Log Mode Name Element);
use Amin::AXA::App;
use Amin::AXA::Store;

# The shop example, for real, in its own namespace (urn:projectamin:example:shop).
# A late-position element filter spliced by _LazyGate on <shop:request> and
# <shop:action> — the plan §4.3 mechanism applied to the app's own elements:
# one filter, element-scoped, declared in the bundle's filter list (the
# adapter merges it into the machine spec at boot, §5.2's machine-first shape).
#
# What flows downstream of this filter is html:* only: the app element is
# swallowed, never forwarded. Output escaping stays in Amin::Handler::HTML
# (§4.5 — HTML never comes from strings, and there is exactly one escaper).
# State lives behind Amin::AXA::Store keyed by the session id the transport
# supplied (§4.7).  It is SQLite-backed, so it survives a prefork worker
# swap — an in-process hash would give each worker its own cart.

use constant SHOP_NS => 'urn:projectamin:example:shop';
use constant XHTML   => 'http://www.w3.org/1999/xhtml';

my $CSS = <<'CSS';
body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1a1d21}
nav.nav{display:flex;gap:1rem;padding:.75rem 1.25rem;background:#1a1d21}
nav.nav a{color:#f6f7f9;text-decoration:none;font-weight:600}
main{max-width:60rem;margin:1.5rem auto;padding:0 1rem}
h1{font-size:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(14rem,1fr));gap:1rem}
.card{background:#fff;border:1px solid #e3e6ea;border-radius:.5rem;padding:1rem}
.card h2{font-size:1.05rem;margin:.25rem 0}
.price{font-weight:700;color:#0a5c2e}
.muted{color:#5b6470;font-size:.9rem}
table{width:100%;border-collapse:collapse;background:#fff}
th,td{padding:.5rem .6rem;border-bottom:1px solid #e3e6ea;text-align:left}
form.inline{display:inline-flex;gap:.4rem;align-items:center}
button{background:#0a5c2e;color:#fff;border:0;border-radius:.35rem;padding:.45rem .8rem;cursor:pointer}
button.secondary{background:#8a1c1c}
input[type=number]{width:4.5rem;padding:.3rem}
.alert{background:#fff4d6;border:1px solid #e0c060;padding:.75rem 1rem;border-radius:.5rem}
a{color:#0a5c2e}
CSS

# ── filter contract: see its own elements, swallow them, emit html ─────
sub start_element ($self, $el) {
    return unless ($el->{NamespaceURI} // '') eq SHOP_NS;
    my $ln = $el->{LocalName} // '';
    my %a = map { (_aname($_)) => ($_->{Value} // '') }
            values %{ $el->{Attributes} // {} };
    if    ($ln eq 'request') { $self->_route(\%a) }
    elsif ($ln eq 'action')  { $self->_action(\%a) }
    return;
}
sub end_element ($self, $el) { return }
sub characters ($self, @)    { return }

sub _aname ($a) { $a->{LocalName} // $a->{Name} // '' }

# ── routing: the declared route attribute drives the page ──────────────
sub _route ($self, $a) {
    my $route = $a->{route} // 'catalog';
    my $cart  = $self->_cart($a->{sid});
    if    ($route eq 'product') { $self->_page_product($a, $cart) }
    elsif ($route eq 'cart')    { $self->_page_cart($a, $cart) }
    else                        { $self->_page_catalog($a, $cart) }
}

# ── actions: cart mutations, then the cart page (no-JS form POST receives
#    a full page — plan §4.6) ──────────────────────────────────────────
#
# Mutations are written back explicitly.  The in-memory adapter used to hand
# out the live record hashref, so mutating the cart in place was enough — but
# that is an accident of one adapter.  A real store (SQLite, and any prefork
# worker pool) returns a fresh deserialized copy on every get(), so in-place
# mutation is silently lost.  Persist explicitly or the cart never changes.
sub _action ($self, $a) {
    my $name = $a->{name} // '';
    my $sku  = $a->{sku}  // '';
    my ($rec, $cart) = $self->_cart_rec($a->{sid});
    if ($name eq 'cart.add' && length $sku) {
        my $qty = ($a->{qty} // '') =~ /^\d+$/ && $a->{qty} > 0 ? 0 + $a->{qty} : 1;
        $cart->{$sku} = ($cart->{$sku} // 0) + $qty;
    }
    elsif ($name eq 'cart.set_qty' && length $sku) {
        my $qty = ($a->{qty} // '') =~ /^\d+$/ ? 0 + $a->{qty} : 0;
        if ($qty > 0) { $cart->{$sku} = $qty } else { delete $cart->{$sku} }
    }
    elsif ($name eq 'cart.remove' && length $sku) {
        delete $cart->{$sku};
    }
    $self->_save_cart($a->{sid}, $rec);
    $self->_page_cart($a, $cart);
}

# read path: (record, cart) — the cart may be undef only when there is no
# session record at all, which routes then treat as empty.
sub _cart_rec ($self, $sid) {
    my $store = Amin::AXA::Store->default;
    my $rec = defined $sid && length $sid ? $store->get($sid) : undef;
    return (undef, {}) unless $rec;
    $rec->{cart} //= {};
    return ($rec, $rec->{cart});
}

sub _save_cart ($self, $sid, $rec) {
    return unless defined $sid && length $sid && defined $rec;
    Amin::AXA::Store->default->set($sid, $rec);
    return;
}

sub _cart ($self, $sid) { my (undef, $cart) = $self->_cart_rec($sid); return $cart }

# ── pages ──────────────────────────────────────────────────────────────
sub _page_catalog ($self, $a, $cart) {
    my $products = Amin::AXA::App->default->catalog;
    $self->_layout('Shop — Catalogue', $cart, sub {
        $self->_start('h1'); $self->_text('Catalogue'); $self->_end('h1');
        if (!@$products) {
            $self->_start('p', class => 'muted'); $self->_text('No products.');
            $self->_end('p'); return;
        }
        $self->_start('div', class => 'grid');
        for my $p ($products->@*) {
            $self->_start('div', class => 'card');
            $self->_start('a', href => '/product?sku=' . _u($p->{sku}));
            $self->_text($p->{name}); $self->_end('a');
            $self->_start('p', class => 'price'); $self->_text(_money($p->{price})); $self->_end('p');
            $self->_start('p', class => 'muted');
            $self->_text(_stock($p->{stock})); $self->_end('p');
            $self->_end('div');
        }
        $self->_end('div');
    });
}

sub _page_product ($self, $a, $cart) {
    my $p = Amin::AXA::App->default->product($a->{sku} // '');
    $self->_layout($p ? "$p->{name} — Shop" : 'Unknown product — Shop', $cart, sub {
        if (!$p) {
            $self->_start('div', class => 'alert');
            $self->_start('strong'); $self->_text('Unknown product: '); $self->_end('strong');
            $self->_text($a->{sku} // '');   # escaped by Handler::HTML
            $self->_end('div');
            $self->_start('p'); $self->_start('a', href => '/');
            $self->_text('Back to catalogue'); $self->_end('a'); $self->_end('p');
            return;
        }
        $self->_start('h1'); $self->_text($p->{name}); $self->_end('h1');
        $self->_start('p', class => 'price'); $self->_text(_money($p->{price})); $self->_end('p');
        $self->_start('p', class => 'muted'); $self->_text(_stock($p->{stock})); $self->_end('p');
        $self->_start('form', method => 'post', action => '/cart');
        $self->_hidden('axa.action', 'cart.add');
        $self->_hidden('axa.param.sku', $p->{sku});
        $self->_hidden('axa.csrf', $a->{csrf} // '');
        $self->_start('button', type => 'submit');
        $self->_text('Add to cart'); $self->_end('button');
        $self->_end('form');
        $self->_start('p'); $self->_start('a', href => '/');
        $self->_text('Back to catalogue'); $self->_end('a'); $self->_end('p');
    });
}

sub _page_cart ($self, $a, $cart) {
    $self->_layout('Cart — Shop', $cart, sub {
        $self->_start('h1'); $self->_text('Your cart'); $self->_end('h1');
        if (!%$cart) {
            $self->_start('p', class => 'muted'); $self->_text('Your cart is empty.');
            $self->_end('p');
            $self->_start('p'); $self->_start('a', href => '/');
            $self->_text('Back to catalogue'); $self->_end('a'); $self->_end('p');
            return;
        }
        my $store = Amin::AXA::Store->default;
        my $total = 0;
        $self->_start('table');
        $self->_start('tr');
        $self->_start('th'); $self->_text('Product'); $self->_end('th');
        $self->_start('th'); $self->_text('Price');   $self->_end('th');
        $self->_start('th'); $self->_text('Qty');     $self->_end('th');
        $self->_start('th'); $self->_text('Total');   $self->_end('th');
        $self->_start('th'); $self->_text('');        $self->_end('th');
        $self->_end('tr');
        for my $sku (sort keys %$cart) {
            my $qty = $cart->{$sku};
            my $p   = Amin::AXA::App->default->product($sku);
            my $price = ($p && $p->{price} =~ /^-?\d+(?:\.\d+)?$/) ? 0 + $p->{price} : 0;
            my $line  = $price * $qty;
            $total += $line;
            $self->_start('tr');
            $self->_start('td'); $self->_text($p ? $p->{name} : $sku); $self->_end('td');
            $self->_start('td'); $self->_text(_money($price));          $self->_end('td');
            $self->_start('td');
            $self->_start('form', class => 'inline', method => 'post', action => '/cart');
            $self->_hidden('axa.action', 'cart.set_qty');
            $self->_hidden('axa.param.sku', $sku);
            $self->_hidden('axa.csrf', $a->{csrf} // '');
            $self->_start('input', type => 'number', name => 'axa.param.qty',
                value => "$qty", min => '0', max => '999');
            $self->_start('button', type => 'submit');
            $self->_text('Update'); $self->_end('button');
            $self->_end('form');
            $self->_end('td');
            $self->_start('td'); $self->_text(_money($line)); $self->_end('td');
            $self->_start('td');
            $self->_start('form', class => 'inline', method => 'post', action => '/cart');
            $self->_hidden('axa.action', 'cart.remove');
            $self->_hidden('axa.param.sku', $sku);
            $self->_hidden('axa.csrf', $a->{csrf} // '');
            $self->_start('button', class => 'secondary', type => 'submit');
            $self->_text('Remove'); $self->_end('button');
            $self->_end('form');
            $self->_end('td');
            $self->_end('tr');
        }
        $self->_start('tr');
        $self->_start('td'); $self->_end('td');
        $self->_start('td'); $self->_end('td');
        $self->_start('td'); $self->_end('td');
        $self->_start('td');
        $self->_start('strong'); $self->_text(_money($total)); $self->_end('strong');
        $self->_end('td');
        $self->_start('td'); $self->_end('td');
        $self->_end('tr');
        $self->_end('table');
        $self->_start('p', class => 'muted');
        $self->_text('Checkout is not wired up in this first pass.');
        $self->_end('p');
        $self->_start('p'); $self->_start('a', href => '/');
        $self->_text('Back to catalogue'); $self->_end('a'); $self->_end('p');
    });
}

sub _layout ($self, $title, $cart, $body) {
    $self->_start('html', lang => 'en');
    $self->_start('head');
    $self->_start('title'); $self->_text($title); $self->_end('title');
    $self->_start('style'); $self->_text($CSS);   $self->_end('style');
    $self->_end('head');
    $self->_start('body');
    $self->_start('nav', class => 'nav');
    $self->_start('a', href => '/');       $self->_text('Catalogue'); $self->_end('a');
    $self->_start('a', href => '/cart');
    $self->_text('Cart (' . scalar(keys %$cart) . ')'); $self->_end('a');
    $self->_end('nav');
    $self->_start('main');
    $body->();
    $self->_end('main');
    $self->_end('body');
    $self->_end('html');
}

# ── html event emission into the inner chain ───────────────────────────
sub _start ($self, $ln, %attrs) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => XHTML, LocalName => $ln, Name => $ln, Prefix => '',
        Attributes => { map {
            ; "{}$_" => { Name => $_, LocalName => $_, Prefix => '',
                          NamespaceURI => XHTML, Value => "$attrs{$_}" }
        } keys %attrs },
    });
    return;
}
sub _end ($self, $ln) {
    my $h = $self->Handler or return;
    $h->end_element({ NamespaceURI => XHTML, LocalName => $ln, Name => $ln,
                      Prefix => '', Attributes => {} });
    return;
}
sub _text ($self, $t) {
    my $h = $self->Handler or return;
    $h->characters({ Data => "$t" });
    return;
}
sub _hidden ($self, $name, $value) {
    $self->_start('input', type => 'hidden', name => $name, value => $value);
    return;
}

sub _money ($v) { sprintf '$%.2f', 0 + $v }
sub _stock ($n) { ($n // '') =~ /^\d+$/ && $n > 0 ? "$n in stock" : 'Out of stock' }
sub _u ($s) { $s =~ s/([^A-Za-z0-9_.\-~])/sprintf '%%%02X', ord $1/ger }

1;
