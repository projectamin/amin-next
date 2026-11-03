package Amin::Example::Shop;
use v5.38; use warnings; use utf8;
use Class::Tiny qw(Handler Log Mode Name Element);
use Amin::AXA::App;
use Amin::AXA::Store;

# The shop example, for real, in its own namespace (urn:projectamin:example:shop).
# A middle-position element filter spliced by _LazyGate on <shop:request> and
# <shop:action> — the plan §4.3 mechanism applied to the app's own elements:
# one filter, element-scoped, declared in the bundle's filter list (the
# adapter merges it into the machine spec at boot, §5.2's machine-first shape).
#
# What flows downstream of this filter is the canonical ui: IR, emitted one
# element at a time through $self->Handler.  It is `middle`, not `late`, on
# purpose: the terminal `late` region holds the ui: Guard and the projection
# fleet, and a middle filter's emitted events flow DOWN through those — a late
# filter's would land below them and reach Handler::HTML unrendered.  So the
# app speaks the closed-world ui: vocabulary and never builds markup: the
# selected Amin::UI::Target::* (Target::HTML, chosen by ui_os=html) turns each
# ui: element into real html:* SAX events, and Amin::Handler::HTML serialises
# and escapes them (§4.5 — one escaper, HTML never built from a string).
#
# State lives behind Amin::AXA::Store keyed by the session id the transport
# supplied (§4.7).  It is SQLite-backed, so it survives a prefork worker
# swap — an in-process hash would give each worker its own cart.

use constant SHOP_NS => 'urn:projectamin:example:shop';
use constant UI_NS   => 'http://projectamin.org/ns/ui/1';

# CSS rides the IR as a ui:style leaf: it projects to <style> in HTML and is a
# no-op in SwiftUI/Compose.  Selectors target the tags the html dialect emits.
my $CSS = <<'CSS';
body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1a1d21}
nav{display:flex;gap:1rem;padding:.75rem 1.25rem;background:#1a1d21}
nav a{color:#f6f7f9;text-decoration:none;font-weight:600}
main{max-width:60rem;margin:1.5rem auto;padding:0 1rem}
article{background:#fff;border:1px solid #e3e6ea;border-radius:.5rem;padding:1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(14rem,1fr));gap:1rem}
table{width:100%;border-collapse:collapse;background:#fff}
th,td{padding:.5rem .6rem;border-bottom:1px solid #e3e6ea;text-align:left}
form{display:inline-flex;gap:.4rem;align-items:center}
button{background:#0a5c2e;color:#fff;border:0;border-radius:.35rem;padding:.45rem .8rem;cursor:pointer}
div[role=alert]{background:#fff4d6;border:1px solid #e0c060;padding:.75rem 1rem;border-radius:.5rem}
a{color:#0a5c2e}
CSS

# ── filter contract: see its own elements, swallow them, emit ui: ─────
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
# Mutations go through Store->update, not get-then-set.  The in-memory
# adapter used to hand out the live record, so an in-place edit stuck by
# accident; a real store returns a fresh copy and needs an explicit write.
# update() is also the critical section: under Starman, two workers can
# POST the same session at once, and a get() outside the write lock lets
# the later set() drop the earlier cart change.
sub _action ($self, $a) {
    my $name = $a->{name} // '';
    my $sku  = $a->{sku}  // '';
    my $sid  = $a->{sid};
    my $cart = {};
    if (defined $sid && length $sid) {
        Amin::AXA::Store->default->update($sid, sub ($rec) {
            return undef unless $rec;
            $rec->{cart} //= {};
            if ($name eq 'cart.add' && length $sku) {
                my $qty = ($a->{qty} // '') =~ /^\d+$/ && $a->{qty} > 0 ? 0 + $a->{qty} : 1;
                $rec->{cart}{$sku} = ($rec->{cart}{$sku} // 0) + $qty;
            }
            elsif ($name eq 'cart.set_qty' && length $sku) {
                my $qty = ($a->{qty} // '') =~ /^\d+$/ ? 0 + $a->{qty} : 0;
                if ($qty > 0) { $rec->{cart}{$sku} = $qty } else { delete $rec->{cart}{$sku} }
            }
            elsif ($name eq 'cart.remove' && length $sku) {
                delete $rec->{cart}{$sku};
            }
            $cart = $rec->{cart};
            return $rec;
        });
    }
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

sub _cart ($self, $sid) { my (undef, $cart) = $self->_cart_rec($sid); return $cart }

# ── pages: emit the canonical ui: IR ──────────────────────────────────
sub _page_catalog ($self, $a, $cart) {
    my $products = Amin::AXA::App->default->catalog;
    $self->_page('Shop — Catalogue', $cart, sub {
        $self->_ui_text_el('Catalogue');
        if (!@$products) {
            $self->_ui_text_el('No products.');
            return;
        }
        $self->_ui_start('grid');
        for my $p ($products->@*) {
            $self->_ui_start('card');
            $self->_ui_start('navigate', to => '/product?sku=' . _u($p->{sku}),
                                      title => $p->{name});
            $self->_ui_end('navigate');
            $self->_ui_text_el(_money($p->{price}));
            $self->_ui_text_el(_stock($p->{stock}));
            $self->_ui_end('card');
        }
        $self->_ui_end('grid');
    });
}

sub _page_product ($self, $a, $cart) {
    my $p = Amin::AXA::App->default->product($a->{sku} // '');
    $self->_page($p ? "$p->{name} — Shop" : 'Unknown product — Shop', $cart, sub {
        if (!$p) {
            $self->_ui_start('alert');
            $self->_ui_text('Unknown product: ' . ($a->{sku} // ''));  # escaped by Handler::HTML
            $self->_ui_end('alert');
            $self->_nav_home;
            return;
        }
        $self->_ui_text_el($p->{name});
        $self->_ui_text_el(_money($p->{price}));
        $self->_ui_text_el(_stock($p->{stock}));
        $self->_ui_start('form', method => 'post', action => '/cart');
        $self->_hidden('axa.action', 'cart.add');
        $self->_hidden('axa.param.sku', $p->{sku});
        $self->_hidden('axa.csrf', $a->{csrf} // '');
        $self->_ui_start('button', title => 'Add to cart');
        $self->_ui_end('button');
        $self->_ui_end('form');
        $self->_nav_home;
    });
}

sub _page_cart ($self, $a, $cart) {
    $self->_page('Cart — Shop', $cart, sub {
        $self->_ui_text_el('Your cart');
        if (!%$cart) {
            $self->_ui_text_el('Your cart is empty.');
            $self->_nav_home;
            return;
        }
        my $total = 0;
        $self->_ui_start('table');
        $self->_ui_start('tr');
        $self->_ui_head_cell($_) for qw(Product Price Qty Total);
        $self->_ui_start('cell'); $self->_ui_end('cell');   # actions column head
        $self->_ui_end('tr');
        for my $sku (sort keys %$cart) {
            my $qty = $cart->{$sku};
            my $p   = Amin::AXA::App->default->product($sku);
            my $price = ($p && $p->{price} =~ /^-?\d+(?:\.\d+)?$/) ? 0 + $p->{price} : 0;
            my $line  = $price * $qty;
            $total += $line;
            $self->_ui_start('tr');
            $self->_ui_cell($p ? $p->{name} : $sku);
            $self->_ui_cell(_money($price));
            $self->_ui_start('cell');
            $self->_ui_start('form', method => 'post', action => '/cart');
            $self->_hidden('axa.action', 'cart.set_qty');
            $self->_hidden('axa.param.sku', $sku);
            $self->_hidden('axa.csrf', $a->{csrf} // '');
            $self->_ui_void('field', type => 'number', name => 'axa.param.qty',
                                    value => "$qty", min => '0', max => '999');
            $self->_ui_start('button', title => 'Update');
            $self->_ui_end('button');
            $self->_ui_end('form');
            $self->_ui_end('cell');
            $self->_ui_cell(_money($line));
            $self->_ui_start('cell');
            $self->_ui_start('form', method => 'post', action => '/cart');
            $self->_hidden('axa.action', 'cart.remove');
            $self->_hidden('axa.param.sku', $sku);
            $self->_hidden('axa.csrf', $a->{csrf} // '');
            $self->_ui_start('button', title => 'Remove');
            $self->_ui_end('button');
            $self->_ui_end('form');
            $self->_ui_end('cell');
            $self->_ui_end('tr');
        }
        $self->_ui_start('tr');
        $self->_ui_start('cell'); $self->_ui_end('cell');
        $self->_ui_start('cell'); $self->_ui_end('cell');
        $self->_ui_start('cell'); $self->_ui_end('cell');
        $self->_ui_cell(_money($total));
        $self->_ui_start('cell'); $self->_ui_end('cell');
        $self->_ui_end('tr');
        $self->_ui_end('table');
        $self->_ui_text_el('Checkout is not wired up in this first pass.');
        $self->_nav_home;
    });
}

# The page shell: ui:app (html/head/title/body) → ui:style → ui:toolbar (nav)
# → ui:scene (main).  Every page shares it.
sub _page ($self, $title, $cart, $body) {
    $self->_ui_start('app', title => $title);
    $self->_ui_start('style'); $self->_ui_text($CSS); $self->_ui_end('style');
    $self->_ui_start('toolbar');
    $self->_ui_start('navigate', to => '/',     title => 'Catalogue');
    $self->_ui_end('navigate');
    $self->_ui_start('navigate', to => '/cart', title => 'Cart (' . scalar(keys %$cart) . ')');
    $self->_ui_end('navigate');
    $self->_ui_end('toolbar');
    $self->_ui_start('scene');
    $body->();
    $self->_ui_end('scene');
    $self->_ui_end('app');
}

# ── ui: IR emission into the inner chain ──────────────────────────────
# An element with character-content (ui:text, ui:label, …).
sub _ui_text_el ($self, $text) {
    $self->_ui_start('text');
    $self->_ui_text($text);
    $self->_ui_end('text');
    return;
}
# A table cell: ui:cell carries a `header` attribute to project to <th>.
sub _ui_cell ($self, $text) {
    $self->_ui_start('cell'); $self->_ui_text($text); $self->_ui_end('cell');
    return;
}
sub _ui_head_cell ($self, $text) {
    $self->_ui_start('cell', header => 1); $self->_ui_text($text); $self->_ui_end('cell');
    return;
}
sub _nav_home ($self) {
    $self->_ui_start('navigate', to => '/', title => 'Back to catalogue');
    $self->_ui_end('navigate');
    return;
}
sub _hidden ($self, $name, $value) {
    $self->_ui_void('field', type => 'hidden', name => $name, value => $value);
    return;
}

sub _ui_start ($self, $ln, %attrs) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => UI_NS, LocalName => $ln, Name => "ui:$ln", Prefix => 'ui',
        Attributes => { map {
            ; "{}${_}" => { Name => $_, LocalName => $_, Prefix => '',
                            NamespaceURI => '', Value => "$attrs{$_}" }
        } keys %attrs },
    });
    return;
}
sub _ui_end ($self, $ln) {
    my $h = $self->Handler or return;
    $h->end_element({ NamespaceURI => UI_NS, LocalName => $ln, Name => "ui:$ln",
                      Prefix => 'ui', Attributes => {} });
    return;
}
sub _ui_text ($self, $t) {
    my $h = $self->Handler or return;
    $h->characters({ Data => "$t" });
    return;
}
# a void ui: element (ui:field → <input>): open + close with no content, so the
# projection's frame stack stays balanced.
sub _ui_void ($self, $ln, %attrs) {
    $self->_ui_start($ln, %attrs);
    $self->_ui_end($ln);
    return;
}

sub _money ($v) { sprintf '$%.2f', 0 + $v }
sub _stock ($n) { ($n // '') =~ /^\d+$/ && $n > 0 ? "$n in stock" : 'Out of stock' }
sub _u ($s) { $s =~ s/([^A-Za-z0-9_.\-~])/sprintf '%%%02X', ord $1/ger }

1;
