#!/usr/bin/env perl
# AXA first pass over HTTP (plan M2 acceptance subset + the session-scoped shop):
#   - GET navigation: catalogue → product → cart; HTML well-formed; no
#     ui:/shop:/amin: leakage in the response
#   - the spec is parsed ONCE at boot (§4.8): the copy the adapter was
#     pointed at is deleted before the first request and every request below
#     still works — a request that re-read machine_spec.xml would fail
#   - the cart is session-scoped (§4.7): it survives across requests within a
#     session and is invisible to a fresh session
#   - framing/hygiene only in the adapter (§5.6): 404 unknown path, 405
#     wrong method, 413 body cap, 415 content-type, 403 bad CSRF/foreign
#     Origin, 422 unknown action — no authorization logic lives here
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use File::Copy qw(copy);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

use Plack::Test;
use HTTP::Request::Common;
use XML::LibXML;
use Amin::AXA::PSGI;

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $APP  = "$ROOT/examples/apps/shop-ui";

# ── §4.8: boot against a COPY of the spec, then delete it ──────────────
my $tmp = tempdir(CLEANUP => 1);
my $spec_copy = "$tmp/machine_spec.xml";
copy("$ROOT/perl-lib/Amin/Machine/machine_spec.xml", $spec_copy) or die "copy: $!";
my $app = Amin::AXA::PSGI->app(app_dir => $APP, machine_spec_path => $spec_copy);
unlink $spec_copy or die "unlink spec copy: $!";
ok(!-e $spec_copy, 'spec copy deleted after boot — requests cannot re-read it');

# Hands the body back a few bytes at a time, so the chunked reader has to
# reassemble a size line and a chunk that arrive in separate reads.
package t51::Drip {
    sub new ($class, $buf) { bless { buf => $buf, at => 0 }, $class }
    # Classic sub so the buffer argument stays the caller's scalar.
    sub read {
        my ($self, undef, $len) = @_;
        my $left = length($self->{buf}) - $self->{at};
        return 0 if $left <= 0;
        my $n = $len > 5 ? 5 : $len;
        $n = $left if $n > $left;
        $_[1] = substr($self->{buf}, $self->{at}, $n);
        $self->{at} += $n;
        return $n;
    }
}

sub csrf_of ($html) { $html =~ /name="axa\.csrf"[^>]*value="([0-9a-f]{64})"/ ? $1 : undef }
sub wellformed ($html, $label) {
    my $ok = eval { XML::LibXML->load_xml(string => $html); 1 };
    ok($ok, "$label is well-formed XHTML") or diag($@);
}

test_psgi $app, sub {
    my $cb = shift;
    my $jar = '';

    my $send = sub ($req) {
        $req->header(Cookie => $jar) if length $jar;
        my $res = $cb->($req);
        if (my $sc = $res->header('Set-Cookie')) {
            $jar = $1 if $sc =~ /(axa_sid=[0-9a-f]{64})/;
        }
        return $res;
    };
    my $get  = sub ($path)     { $send->(GET  "http://localhost$path") };
    my $post = sub ($path, %f) {
        $send->(POST "http://localhost$path",
            Content_Type => 'application/x-www-form-urlencoded',
            Content      => [%f]);
    };

    # ── 1. catalogue ───────────────────────────────────────────────────
    my $r = $get->('/');
    is($r->code, 200, 'GET / → 200');
    like($r->header('Content-Type'), qr{^text/html}, 'GET / is text/html');
    my $html = $r->content;
    like($html, qr/^<!DOCTYPE html>/, 'doctype present');
    like($html, qr/<html lang="en">/, 'one html root with lang');
    like($html, qr/Amin Ceramic Mug/, 'catalogue lists sku-1');
    like($html, qr/Profile Round-trip Poster/, 'catalogue lists sku-5');
    unlike($html, qr/<ui:/,     'no ui: leakage');
    unlike($html, qr{</?shop:}, 'no app-dialect leakage');
    unlike($html, qr{</?amin:}, 'no amin: leakage');
    wellformed($html, 'catalogue page');
    ok(length $jar, 'session cookie minted on first visit');

    # ── 2. product page carries a real CSRF token + action form ────────
    $r = $get->('/product?sku=sku-2');
    is($r->code, 200, 'GET /product → 200');
    $html = $r->content;
    like($html, qr/SAX Filter Tee/, 'product page shows the product');
    like($html, qr/name="axa\.action"[^>]*value="cart\.add"/, 'add-to-cart form declares the action');
    like($html, qr{action="/cart"}, 'form posts to /cart');
    my $csrf = csrf_of($html);
    ok(defined $csrf && length $csrf, 'page carries the session CSRF token');
    wellformed($html, 'product page');

    # ── 3. empty cart ──────────────────────────────────────────────────
    $r = $get->('/cart');
    is($r->code, 200, 'GET /cart → 200');
    like($r->content, qr/Your cart is empty/, 'cart starts empty');

    # ── 4. add: POST action → full page (§4.6 no-JS fallback) ─────────
    $r = $post->('/cart', 'axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1',
                 'axa.csrf' => $csrf);
    is($r->code, 200, 'POST cart.add → 200 full page');
    $html = $r->content;
    like($html, qr/Amin Ceramic Mug/, 'cart page shows the added product');
    like($html, qr/Cart \(1\)/,       'nav shows one line item');
    wellformed($html, 'cart page after add');

    # ── 5. memory: same session still has the cart (§4.7) ──────────────
    $r = $get->('/cart');
    like($r->content, qr/Amin Ceramic Mug/, 'cart persists across requests (in memory)');

    # ── 6. a fresh session sees no cart ────────────────────────────────
    my $saved_jar = $jar; $jar = '';
    $r = $get->('/cart');
    like($r->content, qr/Your cart is empty/, 'fresh session starts empty');
    like($r->header('Set-Cookie') // '', qr/axa_sid=[0-9a-f]{64}/, 'fresh session gets its own cookie');
    $jar = $saved_jar;

    # ── 7. qty update + remove ─────────────────────────────────────────
    $r = $post->('/cart', 'axa.action' => 'cart.set_qty', 'axa.param.sku' => 'sku-1',
                 'axa.param.qty' => '3', 'axa.csrf' => $csrf);
    is($r->code, 200, 'POST cart.set_qty → 200');
    like($r->content, qr/value="3"/, 'quantity updated to 3');
    $r = $post->('/cart', 'axa.action' => 'cart.remove', 'axa.param.sku' => 'sku-1',
                 'axa.csrf' => $csrf);
    like($r->content, qr/Your cart is empty/, 'remove empties the cart');

    # ── 8. framing / hygiene matrix (§5.6 — transport only) ────────────
    $r = $get->('/no-such-path');
    is($r->code, 404, 'unknown path → 404');

    $r = $post->('/product', 'axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1',
                 'axa.csrf' => $csrf);
    is($r->code, 405, 'POST to a GET-only path → 405');

    $r = $post->('/cart', 'axa.action' => 'nope', 'axa.csrf' => $csrf);
    is($r->code, 422, 'unknown action → 422');

    $r = $post->('/cart', 'axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1',
                 'axa.csrf' => ('0' x 64));
    is($r->code, 403, 'bad CSRF → 403');

    $r = $send->(POST 'http://localhost/cart',
        Origin => 'http://evil.example',
        Content_Type => 'application/x-www-form-urlencoded',
        Content => ['axa.action' => 'cart.add', 'axa.param.sku' => 'sku-1', 'axa.csrf' => $csrf]);
    is($r->code, 403, 'foreign Origin on a mutation → 403');

    $r = $send->(POST 'http://localhost/cart',
        Content_Type => 'application/json', Content => '{}');
    is($r->code, 415, 'wrong content-type → 415');

    $r = $send->(POST 'http://localhost/cart',
        Content_Type => 'application/x-www-form-urlencoded',
        Content => ['axa.action' => 'cart.add', 'pad' => 'x' x 300_000]);
    is($r->code, 413, 'body over 256 KiB → 413');

    # No Content-Length (and chunked transfer) must hit the same cap.
    # Checking the header alone treats a missing length as 0 and lets
    # Plack buffer the whole dechunked body.
    my $raw_post = sub ($body, %extra) {
        my $in = delete $extra{input};
        unless ($in) {
            open $in, '<:raw', \$body or die "open body: $!";
        }
        return $app->({
            'psgi.version'      => [1, 1],
            'psgi.url_scheme'   => 'http',
            'psgi.input'        => $in,
            'psgi.errors'       => \*STDERR,
            'psgi.multithread'  => 0,
            'psgi.multiprocess' => 0,
            'psgi.run_once'     => 0,
            REQUEST_METHOD      => 'POST',
            SCRIPT_NAME         => '',
            PATH_INFO           => '/cart',
            SERVER_NAME         => 'localhost',
            SERVER_PORT         => 80,
            SERVER_PROTOCOL     => 'HTTP/1.1',
            CONTENT_TYPE        => 'application/x-www-form-urlencoded',
            HTTP_COOKIE         => $jar,
            %extra,
        });
    };
    my $as_chunks = sub (@parts) {
        my $s = '';
        $s .= sprintf("%x\r\n%s\r\n", length($_), $_) for @parts;
        return $s . "0\r\n\r\n";
    };
    my $over = 'x' x (262_144 + 1);
    my $capped = $raw_post->($over);
    is($capped->[0], 413, 'POST with no Content-Length over 256 KiB → 413');
    $capped = $raw_post->($as_chunks->($over), HTTP_TRANSFER_ENCODING => 'chunked');
    is($capped->[0], 413, 'chunked POST over 256 KiB → 413');
    $capped = $raw_post->($as_chunks->(('y' x 100_000) x 3), HTTP_TRANSFER_ENCODING => 'chunked');
    is($capped->[0], 413, 'chunked POST over 256 KiB across chunks → 413');

    my $form = "axa.action=cart.add&axa.param.sku=sku-2&axa.csrf=$csrf";
    my $mid  = int(length($form) / 2);
    my $chunked_form = $as_chunks->(substr($form, 0, $mid), substr($form, $mid));
    $capped = $raw_post->(
        $chunked_form,
        HTTP_TRANSFER_ENCODING => 'chunked',
        input => t51::Drip->new($chunked_form),
    );
    is($capped->[0], 200, 'chunked POST under the cap is accepted');
    like($capped->[2][0], qr/SAX Filter Tee/, '  and the dechunked body was parsed');

    $r = $send->(PUT 'http://localhost/cart');
    is($r->code, 405, 'unsupported method on a known path → 405');

    # ── 9. reflection is escaped (§4.5) ────────────────────────────────
    $r = $get->('/product?sku=%3Cscript%3Ealert(1)%3C/script%3E');
    is($r->code, 200, 'unknown sku still renders');
    $html = $r->content;
    like($html, qr/&lt;script&gt;alert\(1\)&lt;/, 'raw markup arrives escaped');
    unlike($html, qr/<script>alert\(1\)</, 'no raw script tag in output');
    wellformed($html, 'unknown-product page');
};

# the spec-once property holds for the whole file: nothing re-created it
ok(!-e $spec_copy, 'machine_spec.xml was never re-read (copy still absent)');

done_testing;
