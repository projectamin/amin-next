#!/usr/bin/env perl
# AXA first pass (plan M2 acceptance subset + the session-scoped shop).
#
# Two layers, tested at the layer each lives in.
#
#   Part A — the adapter core (Amin::AXA::HTTP::handle), driven in-process with
#   constructed requests.  Navigation (catalogue → product → cart), the
#   session-scoped cart (§4.7), the spec-once property (§4.8), and the §5.6
#   framing/hygiene matrix (404/405/413/415/403/422) all live here.  No socket,
#   so the assertions are about decisions, not about the wire.
#
#   Part B — the origin's wire handling (Amin::AXA::Serve over Amin::Net::Loop),
#   driven over a real socket: a chunked request body is decoded and parsed, an
#   over-cap body is refused as it arrives, and an oversized request head is
#   refused with 431.  These are transport concerns, so they are tested through
#   the transport.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use File::Copy qw(copy);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use Path::Tiny qw(path);
use XML::LibXML;
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::AXA::HTTP;

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $APP  = "$ROOT/examples/apps/shop-ui";
my $tmp  = tempdir(CLEANUP => 1);

sub wellformed ($html, $label) {
    my $ok = eval { XML::LibXML->load_xml(string => $html); 1 };
    ok($ok, "$label is well-formed XHTML") or diag($@);
}
sub csrf_of ($html) {
    $html =~ /name="axa\.csrf"[^>]*value="([0-9a-f]{64})"/ ? $1 : undef;
}

# ── Part A: the adapter core, in-process ────────────────────────────────
# Boot against a COPY of the app's explicit machine spec, then delete it:
# every request below must still work, proving the spec is resolved ONCE at
# boot and injected per request — a request that re-read it would fail (§4.8).
# The spec explicitly includes amin-core; AXA does no auto-discovery/merge.
my $spec_copy = "$tmp/machine_spec.xml";
copy("$APP/machine_spec.xml", $spec_copy) or die "copy: $!";
my $ctx = Amin::AXA::HTTP->boot(app_dir => $APP, machine_spec_path => $spec_copy);
unlink $spec_copy or die "unlink spec copy: $!";
ok(!-e $spec_copy, 'spec copy deleted after boot — requests cannot re-read it');

# Build the plain request hash the transport hands the core: method, path,
# query, the header pairs, the folded headers, host/scheme/peer, body, and the
# overflow flag.  Exactly the fields Serve fills in from the wire.
sub req (%o) {
    my $headers = $o{headers} // [];
    my %folded;
    $folded{ lc $_->[0] } = $_->[1] for @$headers;
    return {
        method  => $o{method} // 'GET',
        path    => $o{path}   // '/',
        query   => $o{query},
        version => $o{version} // '1.1',
        headers => $headers,
        header  => \%folded,
        host    => $o{host} // 'localhost',
        scheme  => 'http',
        peer    => '127.0.0.1',
        body    => $o{body} // '',
        body_overflow => $o{body_overflow} // 0,
    };
}

my $jar = '';
sub _call ($r) {
    my %header  = %{ $r->{header} };
    my @headers = @{ $r->{headers} };
    if (length $jar) {                 # the cookie jar, as a browser would send it
        $header{cookie} = $jar;
        push @headers, ['Cookie' => $jar];
    }
    my $res = Amin::AXA::HTTP->handle(
        $ctx, { %$r, headers => \@headers, header => \%header }, stream => 0);
    die "core unexpectedly returned a streaming coderef" if ref $res eq 'CODE';
    my (%h, @flat);
    my $hs = $res->[1];
    for (my $i = 0; $i + 1 < @$hs; $i += 2) {
        push @{ $h{ lc $hs->[$i] } }, $hs->[$i + 1];
        push @flat, $hs->[$i], $hs->[$i + 1];
    }
    if (my ($sc) = @{ $h{'set-cookie'} // [] }) {
        $jar = $1 if $sc =~ /(axa_sid=[0-9a-f]{64})/;
    }
    return { status => $res->[0], headers => \%h, flat => \@flat, body => $res->[2] };
}

my $get = sub ($path, $query = undef) {
    _call(req(method => 'GET', path => $path, query => $query,
             headers => [['Host' => 'localhost']]));
};
my $post = sub ($path, %f) {
    my $body = join '&', map { "$_=" . _form_enc($f{$_}) } sort keys %f;
    _call(req(method => 'POST', path => $path, body => $body,
             headers => [['Host' => 'localhost'],
                         ['Content-Type' => 'application/x-www-form-urlencoded']]));
};
sub _form_enc ($v) { $v =~ s/([^A-Za-z0-9_.\-])/sprintf('%%%02X', ord $1)/ge; return $v }

# ── 1. catalogue ───────────────────────────────────────────────────────
my $r = $get->('/');
is($r->{status}, 200, 'GET / → 200');
like($r->{headers}{'content-type'}[0], qr{^text/html}, 'GET / is text/html');
my $html = $r->{body};
like($html, qr/^<!DOCTYPE html>/, 'doctype present');
like($html, qr/<html lang="en">/, 'one html root with lang');
like($html, qr/Amin Ceramic Mug/, 'catalogue lists sku-1');
like($html, qr/Profile Round-trip Poster/, 'catalogue lists sku-5');
unlike($html, qr/<ui:/,     'no ui: leakage');
unlike($html, qr{</?shop:}, 'no app-dialect leakage');
unlike($html, qr{</?amin:}, 'no amin: leakage');
wellformed($html, 'catalogue page');
ok(length $jar, 'session cookie minted on first visit');

# ── 2. product page carries a real CSRF token + action form ────────────
$r = $get->('/product', 'sku=sku-2');
is($r->{status}, 200, 'GET /product → 200');
$html = $r->{body};
like($html, qr/SAX Filter Tee/, 'product page shows the product');
like($html, qr/name="axa\.action"[^>]*value="cart\.add"/, 'add-to-cart form declares the action');
like($html, qr{action="/cart"}, 'form posts to /cart');
my $csrf = csrf_of($html);
ok(defined $csrf && length $csrf, 'page carries the session CSRF token');
wellformed($html, 'product page');

# ── 3. empty cart ──────────────────────────────────────────────────────
$r = $get->('/cart');
is($r->{status}, 200, 'GET /cart → 200');
like($r->{body}, qr/Your cart is empty/, 'cart starts empty');

# ── 4. add: POST action → full page (§4.6 no-JS fallback) ─────────────
$r = $post->('/cart', 'axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1',
             'axa.csrf' => $csrf);
is($r->{status}, 200, 'POST cart.add → 200 full page');
$html = $r->{body};
like($html, qr/Amin Ceramic Mug/, 'cart page shows the added product');
like($html, qr/Cart \(1\)/,       'nav shows one line item');
wellformed($html, 'cart page after add');

# ── 5. memory: same session still has the cart (§4.7) ──────────────────
$r = $get->('/cart');
like($r->{body}, qr/Amin Ceramic Mug/, 'cart persists across requests (in memory)');

# ── 6. a fresh session sees no cart ────────────────────────────────────
my $saved_jar = $jar; $jar = '';
$r = $get->('/cart');
like($r->{body}, qr/Your cart is empty/, 'fresh session starts empty');
like($r->{headers}{'set-cookie'}[0] // '', qr/axa_sid=[0-9a-f]{64}/, 'fresh session gets its own cookie');
$jar = $saved_jar;

# ── 7. qty update + remove ─────────────────────────────────────────────
$r = $post->('/cart', 'axa.action' => 'cart.set_qty', 'axa.param.sku' => 'sku-1',
             'axa.param.qty' => '3', 'axa.csrf' => $csrf);
is($r->{status}, 200, 'POST cart.set_qty → 200');
like($r->{body}, qr/value="3"/, 'quantity updated to 3');
$r = $post->('/cart', 'axa.action' => 'cart.remove', 'axa.param.sku' => 'sku-1',
             'axa.csrf' => $csrf);
like($r->{body}, qr/Your cart is empty/, 'remove empties the cart');

# ── 8. framing / hygiene matrix (§5.6 — transport only) ────────────────
$r = $get->('/no-such-path');
is($r->{status}, 404, 'unknown path → 404');

$r = $post->('/product', 'axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1',
             'axa.csrf' => $csrf);
is($r->{status}, 405, 'POST to a GET-only path → 405');

$r = $post->('/cart', 'axa.action' => 'nope', 'axa.csrf' => $csrf);
is($r->{status}, 422, 'unknown action → 422');

$r = $post->('/cart', 'axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1',
             'axa.csrf' => ('0' x 64));
is($r->{status}, 403, 'bad CSRF → 403');

$r = _call(req(method => 'POST', path => '/cart',
    headers => [['Host' => 'localhost'], ['Origin' => 'http://evil.example'],
                ['Content-Type' => 'application/x-www-form-urlencoded']],
    body => "axa.action=cart.add&axa.param.sku=sku-1&axa.csrf=$csrf"));
is($r->{status}, 403, 'foreign Origin on a mutation → 403');

$r = _call(req(method => 'POST', path => '/cart',
    headers => [['Host' => 'localhost'], ['Content-Type' => 'application/json']],
    body => '{}'));
is($r->{status}, 415, 'wrong content-type → 415');

# An over-cap body is flagged by the transport (Serve stops reading at the cap
# and sets body_overflow); the core turns that into a 413 without buffering.
$r = _call(req(method => 'POST', path => '/cart', body_overflow => 1,
    headers => [['Host' => 'localhost'],
                ['Content-Type' => 'application/x-www-form-urlencoded']],
    body => 'x' x 10));
is($r->{status}, 413, 'body over the cap → 413');

# ── 9. reflection is escaped (§4.5) ────────────────────────────────────
$r = $get->('/product', 'sku=%3Cscript%3Ealert(1)%3C/script%3E');
is($r->{status}, 200, 'unknown sku still renders');
$html = $r->{body};
like($html, qr/&lt;script&gt;alert\(1\)&lt;/, 'raw markup arrives escaped');
unlike($html, qr/<script>alert\(1\)</, 'no raw script tag in output');
wellformed($html, 'unknown-product page');

# the spec-once property holds for the whole core run: nothing re-created it
ok(!-e $spec_copy, 'machine_spec.xml was never re-read (copy still absent)');

# ── Part B: the origin's wire handling, over a real socket ──────────────
my $probe = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1,
) or die "cannot pick a port: $!";
my $port = $probe->sockport;
close $probe;

my $pid = fork();
die "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    open STDOUT, '>>', "$tmp/serve.stderr" or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    local $ENV{AXA_STORE} = "$tmp/store.sqlite";
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/axa",
        $APP, '--listen', "127.0.0.1:$port", '--workers', 1;
    exit 127;
}
END { kill 'TERM', $pid if $pid }

my $ready;
for (1 .. 150) {
    $ready = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1);
    # IO::Socket::INET 1.52 with Timeout hands back a socket for a refused
    # connect, so the handle alone is not proof of a listener.
    last if $ready && $ready->connected;
    sleep 0.1;
}
ok($ready, "origin listening on 127.0.0.1:$port")
    or do { diag("server log:\n" . path("$tmp/serve.stderr")->slurp); done_testing(); exit 1 };
close $ready;

# Send a raw request with Connection: close, read the whole response to EOF.
sub raw ($text) {
    my $s = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 5)
        or return '';
    return '' unless $s->connected;
    print $s $text;
    $s->blocking(0);
    my $buf = '';
    my $deadline = time + 6;
    while (time < $deadline) {
        my $n = sysread($s, my $chunk, 65536);
        if (defined $n && $n > 0) { $buf .= $chunk; next }
        last if defined $n && $n == 0;
        sleep 0.02;
    }
    close $s;
    return $buf;
}

my $home = raw("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
my ($sid) = $home =~ /Set-Cookie:\s*(axa_sid=[0-9a-f]{64})/i;
ok($sid, 'origin minted a session cookie');

my $prod = raw("GET /product?sku=sku-2 HTTP/1.1\r\nHost: localhost\r\n"
             . "Cookie: $sid\r\nConnection: close\r\n\r\n");
my ($tok) = $prod =~ /name="axa\.csrf"[^>]*value="([0-9a-f]{64})"/;
ok($tok, 'csrf token read back over the wire');

# A chunked request body must be decoded and parsed by the origin.  Split the
# form across two chunks so the decoder has to reassemble framing + payload.
my $form = "axa.action=cart.add&axa.param.sku=sku-2&axa.csrf=$tok";
my $mid  = int(length($form) / 2);
my $chunked = sprintf("%x\r\n%s\r\n", length(substr($form, 0, $mid)), substr($form, 0, $mid))
            . sprintf("%x\r\n%s\r\n", length(substr($form, $mid)),    substr($form, $mid))
            . "0\r\n\r\n";
my $cr = raw("POST /cart HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n"
           . "Content-Type: application/x-www-form-urlencoded\r\n"
           . "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" . $chunked);
like($cr, qr{^HTTP/1\.1 200}, 'chunked request body accepted');
like($cr, qr/SAX Filter Tee/, '  and the de-chunked body was parsed');

# Over the cap while chunked: refused as it arrives (decoded-byte cap), and the
# connection closes rather than mis-parsing the leftovers.
my $big  = 'x' x 100_000;
my $over = (sprintf("%x\r\n%s\r\n", length($big), $big)) x 3 . "0\r\n\r\n";
my $or = raw("POST /cart HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n"
           . "Content-Type: application/x-www-form-urlencoded\r\n"
           . "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" . $over);
like($or, qr{^HTTP/1\.1 413}, 'chunked request body over the cap → 413');

# An oversized request head is refused with 431 rather than buffered forever.
my $pad = 'a' x 70_000;
my $hr = raw("GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: $pad\r\nConnection: close\r\n\r\n");
like($hr, qr{^HTTP/1\.1 431}, 'oversized request head → 431');

kill 'TERM', $pid;
waitpid $pid, 0;
$pid = 0;

done_testing;
