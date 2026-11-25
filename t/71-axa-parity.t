#!/usr/bin/env perl
# Perl ↔ Rust parity for the AXA origin (proxy-plan §7/§8, P4): one app bundle
# (examples/apps/shop-ui) served by the Perl adapter (`bin/axa`) and
# by the Rust peer (`amin-axa`), each fed the same raw requests over real
# sockets.
#
# The §7 rule is byte-identical *pages*: the same `<axa:app>` declarations, the
# same request, must render the same HTML under both implementations — the
# element filters, the ui: filters, the projection tables and the serializer
# are all ported, so nothing here is allowed to drift.  The Perl and Rust
# streams are compared directly, body against body.
#
# The one value a page cannot share across two processes is the session's
# opaque 64-hex CSRF token (and the sid on Set-Cookie): each front mints its
# own.  Those runs are normalised to a placeholder before a page that embeds
# one is compared, so every other byte must still match exactly.
#
# Nothing here is mocked: two real front processes, real sockets, real bytes.
#
# The Perl front streams through Amin::Net::Loop (Amin::AXA::Serve), so its
# response is `Transfer-Encoding: chunked` (one small chunk per emitted
# element) with no `Content-Length`; the Rust front buffers and sets
# `Content-Length`.  The framing differs, so the Perl body is de-chunked
# before comparison — the rendered bytes underneath are what must agree.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Acme::Key;

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $APP  = "$ROOT/examples/apps/shop-ui";
# Cargo's target dir is centralised in .mise.toml / CI (CARGO_TARGET_DIR), so
# look there first; the in-crate target is only a legacy fallback for a bare
# `cargo build -p amin-axa` run from ./rust.
my $RUST = do {
    my $dir = defined $ENV{CARGO_TARGET_DIR} && length $ENV{CARGO_TARGET_DIR}
        ? $ENV{CARGO_TARGET_DIR} : "$ROOT/rust/target";
    "$dir/debug/amin-axa";
};
$RUST = "$ROOT/rust/target/debug/amin-axa" unless -x $RUST;
unless (-x $RUST) {
    skip_all "amin-axa not compiled; run `cargo build -p amin-axa --manifest-path rust/Cargo.toml`";
}

# ── socket helpers (mirrors t/70) ───────────────────────────────────────────

sub free_port () {
    my $p = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1,
    ) or die "cannot pick a port: $!";
    my $port = $p->sockport;
    close $p;
    return $port;
}

sub wait_listen ($port, $tries = 150) {
    for (1 .. $tries) {
        my $s = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1,
        );
        # IO::Socket::INET 1.52 with Timeout hands back a socket even when the
        # non-blocking connect was refused (SO_ERROR=ECONNREFUSED), so the
        # handle alone is not proof of a listener: a refused socket is not
        # `connected`.
        return 1 if $s && $s->connected;
        sleep 0.1;
    }
    return 0;
}

# Send a raw request, read the whole response to EOF (both fronts close).
#
# `Connection: close` is pinned onto every request so the front closes the
# moment it has answered: the loop origin would otherwise hold the connection
# open for its keepalive window, stalling the Perl side of every comparison.
# It changes only the response's own framing headers, never the body compared.
sub send_raw ($port, $raw, $timeout = 6) {
    $raw =~ s/\r\n\r\n/\r\nConnection: close\r\n\r\n/ unless $raw =~ /\r\nConnection:/i;
    my $s = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => $timeout,
    ) or return undef;
    return undef unless $s->connected;
    print $s $raw;
    my $resp = '';
    while (1) {
        my $rin = ''; vec($rin, fileno($s), 1) = 1;
        last unless select(my $r = $rin, undef, undef, $timeout);
        my $n = sysread($s, my $chunk, 65536);
        last unless defined $n && $n > 0;
        $resp .= $chunk;
    }
    close $s;
    return $resp;
}

# Split a response into its head and body, de-chunking the body when the head
# says the transfer is chunked (the loop/streamed case).
sub dechunk ($resp) {
    my ($head, $body) = split /\r\n\r\n/, $resp // '', 2;
    $head //= '';
    $body //= '';
    return ($head, $body) unless $head =~ /transfer-encoding:\s*[^\r\n]*chunked/i;
    my $out = '';
    while (length $body) {
        $body =~ s/^([0-9a-fA-F]+)[^\r\n]*\r\n// or last;
        my $len = hex $1;
        last if $len == 0;
        $out .= substr($body, 0, $len);
        substr($body, 0, $len + 2) = '';
    }
    return ($head, $out);
}

# Turn a raw response into the comparable page: status code, content type, the
# Set-Cookie sid (if any), and the (de-chunked) body.
sub page ($port, $raw) {
    my ($head, $body) = dechunk(send_raw($port, $raw));
    my ($status) = $head =~ m{^HTTP/1\.\d (\d+)};
    my ($ct)     = $head =~ /\r\nContent-Type:\s*([^\r\n]*)/i;
    my ($sid)    = $head =~ /Set-Cookie:\s*(axa_sid=[0-9a-f]{64})/i;
    return { status => $status, ct => $ct, sid => $sid, body => $body };
}

# Replace the per-process random session material (the 64-hex CSRF token, and
# the sid if it ever leaked into a body) with a fixed placeholder.
sub uniq_tokens ($s) { $s =~ s/[0-9a-f]{64}/<TOKEN>/g; return $s }

sub csrf_of ($body) { $body =~ /name="axa\.csrf"[^>]*value="([0-9a-f]{64})"/ ? $1 : undef }

# ── the two fronts, one bundle ──────────────────────────────────────────────
my $tmp       = tempdir(CLEANUP => 1);
my $perl_port = free_port();
my $rust_port = free_port();
my $perl_log  = "$tmp/perl.stderr";
my $rust_log  = "$tmp/rust.stderr";
my $db        = "$tmp/store.sqlite";

my $perl_front = fork();
die "fork failed: $!" unless defined $perl_front;
if ($perl_front == 0) {
    open STDOUT, '>>', $perl_log or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    # Keep the session store inside the test's tempdir.
    local $ENV{AXA_STORE} = $db;
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/axa",
        $APP,
        '--listen', "127.0.0.1:$perl_port",
        '--workers', 1;
    exit 127;
}

my $rust_front = fork();
die "fork failed: $!" unless defined $rust_front;
if ($rust_front == 0) {
    open STDOUT, '>>', $rust_log or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    exec $RUST, '--app', $APP, '--listen', "127.0.0.1:$rust_port";
    exit 127;
}

my $up = wait_listen($perl_port) && wait_listen($rust_port);
ok($up, "perl front on :$perl_port and rust front on :$rust_port")
    or do {
        kill 'TERM', $perl_front, $rust_front;
        waitpid $_, 0 for $perl_front, $rust_front;
        diag('perl front log: ' . (-f $perl_log ? path($perl_log)->slurp : '(none)'));
        diag('rust front log: ' . (-f $rust_log ? path($rust_log)->slurp : '(none)'));
        done_testing(); exit 1;
    };

# Send the same raw bytes to both fronts; return the two pages.
sub both ($raw) {
    return (page($perl_port, $raw), page($rust_port, $raw));
}

# Mint a session on one front and read its CSRF token back off a page that
# carried the cookie.
sub new_session ($port) {
    my $home = page($port, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    my $sid  = $home->{sid};
    my $prod = page($port, "GET /product?sku=sku-2 HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n\r\n");
    return ($sid, csrf_of($prod->{body}));
}

# ── 1. the catalogue: no session data, so byte for byte ─────────────────────
subtest 'GET / renders a byte-identical catalogue' => sub {
    my ($p, $r) = both("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    is $p->{status}, 200, 'perl 200';
    is $r->{status}, 200, 'rust 200';
    is $p->{ct}, $r->{ct}, 'the same Content-Type';
    like $p->{ct}, qr{^text/html}, 'served as text/html';
    is $r->{body}, $p->{body}, 'the catalogue page is byte-identical';
    like $p->{body}, qr{^<!DOCTYPE html>}, 'doctype present';
    like $p->{body}, qr/Amin Ceramic Mug/, 'catalogue content present';
    unlike $p->{body}, qr{</?shop:}, 'no app-dialect leakage';
};

# ── 2. the empty cart: also session-free, byte for byte ─────────────────────
subtest 'GET /cart (empty) is byte-identical' => sub {
    my ($p, $r) = both("GET /cart HTTP/1.1\r\nHost: localhost\r\n\r\n");
    is $p->{status}, 200, 'perl 200';
    is $r->{status}, 200, 'rust 200';
    is $r->{body}, $p->{body}, 'the empty-cart page is byte-identical';
    like $p->{body}, qr/Your cart is empty/, 'cart is empty';
};

# ── 3. a page that embeds the CSRF: identical modulo the token ──────────────
subtest 'GET /product is identical modulo the session token' => sub {
    my ($p, $r) = both("GET /product?sku=sku-2 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    is $p->{status}, 200, 'perl 200';
    is $r->{status}, 200, 'rust 200';
    is length($r->{body}), length($p->{body}), 'same page length';
    is uniq_tokens($r->{body}), uniq_tokens($p->{body}),
        'the product page is identical modulo the CSRF token';
    like $p->{body}, qr/SAX Filter Tee/, 'the product is shown';
    like $p->{body}, qr/name="axa\.csrf"[^>]*value="[0-9a-f]{64}"/,
        'the form embeds a session CSRF token';
    like $p->{body}, qr{action="/cart"}, 'the add form posts to /cart';
};

# ── 4. reflection is escaped the same way (§4.5, one escaper) ───────────────
subtest 'an unknown-product reflection is escaped identically' => sub {
    my ($p, $r) = both(
        "GET /product?sku=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: localhost\r\n\r\n");
    is $p->{status}, 200, 'perl 200';
    is $r->{status}, 200, 'rust 200';
    is $r->{body}, $p->{body}, 'the reflection page is byte-identical';
    like $p->{body}, qr/&lt;script&gt;alert\(1\)&lt;/, 'raw markup arrives escaped';
    unlike $p->{body}, qr{<script>alert\(1\)<}, 'no raw script tag in the output';
};

# ── 5. the framing matrix (§5.6) answers identically ────────────────────────
subtest 'the framing matrix answers identically' => sub {
    my @cases = (
        ['GET /no-such-path',   404,
            "GET /no-such-path HTTP/1.1\r\nHost: localhost\r\n\r\n"],
        ['POST to a GET-only path', 405,
            "POST /product HTTP/1.1\r\nHost: localhost\r\n"
          . "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n"],
        ['wrong content-type',  415,
            "POST /cart HTTP/1.1\r\nHost: localhost\r\n"
          . "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"],
    );
    for my $c (@cases) {
        my ($label, $code, $raw) = @$c;
        my ($p, $r) = both($raw);
        is $p->{status}, $code, "perl: $label → $code";
        is $r->{status}, $code, "rust: $label → $code";
        is $r->{body}, $p->{body}, "$label: the error body is byte-identical";
    }
};

# ── 6. a session-scoped mutation renders identically ────────────────────────
subtest 'a session-scoped cart add renders identically modulo the token' => sub {
    my %cart;
    for my $side ([perl => $perl_port], [rust => $rust_port]) {
        my ($name, $port) = @$side;
        my ($sid, $tok) = new_session($port);
        ok $sid, "$name minted a session cookie";
        ok $tok, "$name product page carried a CSRF token";

        my $form = "axa.action=cart.add&axa.param.sku=sku-1&axa.csrf=$tok";
        my $post = page($port,
            "POST /cart HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n"
          . "Content-Type: application/x-www-form-urlencoded\r\n"
          . 'Content-Length: ' . length($form) . "\r\n\r\n$form");
        $cart{$name} = $post;
        is $post->{status}, 200, "$name POST cart.add → 200 full page";
        like $post->{body}, qr/Amin Ceramic Mug/, "$name cart shows the added product";
        like $post->{body}, qr/Cart \(1\)/, "$name nav shows one line item";

        # §4.7: the cart persists on a later request in the same session.
        my $again = page($port, "GET /cart HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n\r\n");
        like $again->{body}, qr/Amin Ceramic Mug/, "$name cart persists across requests";
        is uniq_tokens($again->{body}), uniq_tokens($post->{body}),
            "$name the later GET equals the POST response modulo the token";
    }
    is length($cart{rust}{body}), length($cart{perl}{body}), 'same cart page length';
    is uniq_tokens($cart{rust}{body}), uniq_tokens($cart{perl}{body}),
        'the cart page is identical modulo the session token';
};

# ── 7. action errors answer identically (status + body) ─────────────────────
# The reason phrase is the front's own text (RFC 9110 names 422 differently in
# each stack), so only the numeric status and the body are compared — the body
# is the app's, and it must be byte-identical.
subtest 'an unknown action and a foreign Origin are refused identically' => sub {
    my %out;
    for my $side ([perl => $perl_port], [rust => $rust_port]) {
        my ($name, $port) = @$side;
        my ($sid, $tok) = new_session($port);

        my $bad = "axa.action=nope&axa.csrf=$tok";
        $out{$name}{unknown} = page($port,
            "POST /cart HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n"
          . "Content-Type: application/x-www-form-urlencoded\r\n"
          . 'Content-Length: ' . length($bad) . "\r\n\r\n$bad");

        my $form = "axa.action=cart.add&axa.param.sku=sku-1&axa.csrf=$tok";
        $out{$name}{origin} = page($port,
            "POST /cart HTTP/1.1\r\nHost: localhost\r\nCookie: $sid\r\n"
          . "Origin: http://evil.example\r\n"
          . "Content-Type: application/x-www-form-urlencoded\r\n"
          . 'Content-Length: ' . length($form) . "\r\n\r\n$form");
    }
    is $out{perl}{unknown}{status}, 422, 'perl unknown action → 422';
    is $out{rust}{unknown}{status}, 422, 'rust unknown action → 422';
    is $out{rust}{unknown}{body}, $out{perl}{unknown}{body},
        'the unknown-action body is byte-identical';

    is $out{perl}{origin}{status}, 403, 'perl foreign Origin → 403';
    is $out{rust}{origin}{status}, 403, 'rust foreign Origin → 403';
    is $out{rust}{origin}{body}, $out{perl}{origin}{body},
        'the foreign-Origin body is byte-identical';
};

# ── 8. a path-template, plain-text route is byte-identical ──────────────────
# The route `/hello/:who` declares type="text/plain": the `:who` segment is
# captured (raw, never percent-decoded) and substituted into the fragment, and
# the response body is that text verbatim — no doctype, no escaping, served as
# text/plain.  Both fronts must agree byte for byte.
subtest 'a text/plain path-template route is byte-identical' => sub {
    for my $case (
        ['plain segment',  '/hello/ada',       'Hello, ada!'],
        ['raw capture',    '/hello/a%20b',     'Hello, a%20b!'],
    ) {
        my ($label, $path, $want) = @$case;
        my ($p, $r) = both("GET $path HTTP/1.1\r\nHost: localhost\r\n\r\n");
        is $p->{status}, 200, "perl 200 ($label)";
        is $r->{status}, 200, "rust 200 ($label)";
        is $p->{ct}, $r->{ct}, "the same Content-Type ($label)";
        like $p->{ct}, qr{^text/plain}, "served as text/plain ($label)";
        is $p->{body}, "$want\n", "perl emits the verbatim body ($label)";
        is $r->{body}, $p->{body}, "the body is byte-identical ($label)";
    }

    # A template only matches a path with the same segment count: `/hello`
    # (one segment) can never satisfy `/hello/:who`.
    my ($p, $r) = both("GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n");
    is $p->{status}, 404, 'perl 404 when the template cannot match';
    is $r->{status}, 404, 'rust 404 when the template cannot match';
    is $r->{body}, $p->{body}, 'the 404 body is byte-identical';
};

# ── 9. a ui: route fragment renders identically, theme included ─────────────
# A route may carry canonical `ui:` IR directly; both fronts project it through
# the same target.  The sheet is shared source (the Rust target embeds the
# Perl target's themes/*.css), so the themed page is the parity contract: any
# reflow of a theme on one side fails here, not in a user's browser.
subtest 'a themed ui: route fragment is byte-identical' => sub {
    my $tdir = tempdir(CLEANUP => 1);
    path("$tdir/axa.xml")->spew_utf8(<<~'XML');
        <?xml version="1.0" encoding="UTF-8"?>
        <axa:app xmlns:axa="http://projectamin.org/ns/axa/1"
                 id="io.projectamin.test.theme" name="theme">
          <axa:route path="/studio" method="GET">
            <ui:app xmlns:ui="http://projectamin.org/ns/ui/1" title="Studio" theme="soft-studio">
              <ui:vstack title="lane">
                <ui:text title="hello">hello</ui:text>
                <ui:visualizer mode="vortex" id="hero"/>
              </ui:vstack>
            </ui:app>
          </axa:route>
          <axa:route path="/falls-back" method="GET">
            <ui:app xmlns:ui="http://projectamin.org/ns/ui/1" title="Bogus" theme="not-a-theme">
              <ui:text title="hi">hi</ui:text>
            </ui:app>
          </axa:route>
        </axa:app>
        XML
    path("$tdir/machine_spec.xml")->spew_utf8(<<~'XML');
        <?xml version="1.0" encoding="UTF-8"?>
        <amin:machine xmlns:amin="http://projectamin.org/ns/2026/" name="theme">
          <amin:include spec="amin-core" />
        </amin:machine>
        XML

    my $pp = free_port();
    my $rp = free_port();
    my $pf = fork();
    die "fork failed: $!" unless defined $pf;
    if ($pf == 0) {
        open STDOUT, '>>', "$tdir/perl.stderr" or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/axa",
            $tdir, '--listen', "127.0.0.1:$pp", '--workers', 1;
        exit 127;
    }
    my $rf = fork();
    die "fork failed: $!" unless defined $rf;
    if ($rf == 0) {
        open STDOUT, '>>', "$tdir/rust.stderr" or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $RUST, '--app', $tdir, '--listen', "127.0.0.1:$rp";
        exit 127;
    }

    my $up = wait_listen($pp) && wait_listen($rp);
    ok($up, "theme fronts up (perl :$pp, rust :$rp)")
        or do {
            kill 'TERM', $pf, $rf;
            waitpid $_, 0 for $pf, $rf;
            diag('perl front log: ' . (-f "$tdir/perl.stderr" ? path("$tdir/perl.stderr")->slurp : '(none)'));
            diag('rust front log: ' . (-f "$tdir/rust.stderr" ? path("$tdir/rust.stderr")->slurp : '(none)'));
            return;
        };

    for my $case (
        ['soft-studio', '/studio',     qr/--nz-signal:/],
        ['fallback',    '/falls-back', qr/--md-primary:#6750a4/],
    ) {
        my ($label, $path, $want) = @$case;
        my $p = page($pp, "GET $path HTTP/1.1\r\nHost: localhost\r\n\r\n");
        my $r = page($rp, "GET $path HTTP/1.1\r\nHost: localhost\r\n\r\n");
        is $p->{status}, 200, "perl 200 ($label)";
        is $r->{status}, 200, "rust 200 ($label)";
        like $p->{body}, $want, "perl selected the right sheet ($label)";
        is $r->{body}, $p->{body}, "the themed page is byte-identical ($label)";
        is scalar(() = $p->{body} =~ /<style>/g), 1, "exactly one <style> ($label)";
    }

    kill 'TERM', $pf, $rf;
    waitpid $_, 0 for $pf, $rf;
};

# ── 10. the ACME HTTP-01 responder is byte-identical (proxy-plan §5.5) ──────
# ACME is an app-level filter, not a proxy concern: the bundle's own
# machine_spec.xml declares it, and the CA fetches
# `/.well-known/acme-challenge/<token>` expecting the RFC 8555 key
# authorization (`token "." thumbprint(account key)`) as the text/plain body.
# Both fronts must derive the same RFC 7638 thumbprint from the same account
# key and emit the same bytes — the responders are pure functions of the key.
subtest 'the ACME HTTP-01 responder is byte-identical' => sub {
    my ($openssl) = grep { -x "$_/openssl" } split /:/, $ENV{PATH} // '';
    if (!$openssl) {
        skip_all 'openssl CLI not found on PATH (Amin::Acme::Key shells out to it)';
        return;
    }

    # A self-contained bundle whose own machine_spec.xml declares the responder
    # with a freshly generated account key both fronts can read.
    my $adir = tempdir(CLEANUP => 1);
    my $akey = "$adir/account.key";
    Amin::Acme::Key->gen_ec($akey);
    my $akey_obj = Amin::Acme::Key->new(path => $akey);

    path("$adir/axa.xml")->spew_utf8(<<~"XML");
        <?xml version="1.0" encoding="UTF-8"?>
        <axa:app xmlns:axa="http://projectamin.org/ns/axa/1"
                 xmlns:amin="http://projectamin.org/ns/2026/"
                 id="io.projectamin.test.acme" name="acme">
          <axa:route path="/.well-known/acme-challenge/:token" method="GET" type="text/plain"><amin:acme-challenge token="{token}"/></axa:route>
        </axa:app>
        XML
    path("$adir/machine_spec.xml")->spew_utf8(<<~"XML");
        <?xml version="1.0" encoding="UTF-8"?>
        <amin:machine xmlns:amin="http://projectamin.org/ns/2026/">
          <filter class="Amin::Filter::Acme" position="middle"
                  element="acme-challenge" namespace="http://projectamin.org/ns/2026/"
                  key="$akey" />
        </amin:machine>
        XML

    my $pp = free_port();
    my $rp = free_port();
    my $pl = "$adir/perl.stderr";
    my $rl = "$adir/rust.stderr";

    my $pf = fork();
    die "fork failed: $!" unless defined $pf;
    if ($pf == 0) {
        open STDOUT, '>>', $pl or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/axa",
            $adir,
            '--listen', "127.0.0.1:$pp", '--workers', 1;
        exit 127;
    }

    my $rf = fork();
    die "fork failed: $!" unless defined $rf;
    if ($rf == 0) {
        open STDOUT, '>>', $rl or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $RUST, '--app', $adir, '--listen', "127.0.0.1:$rp";
        exit 127;
    }

    my $up = wait_listen($pp) && wait_listen($rp);
    ok($up, "acme fronts up (perl :$pp, rust :$rp)")
        or do {
            kill 'TERM', $pf, $rf;
            waitpid $_, 0 for $pf, $rf;
            diag('perl front log: ' . (-f $pl ? path($pl)->slurp : '(none)'));
            diag('rust front log: ' . (-f $rl ? path($rl)->slurp : '(none)'));
            return;
        };

    # Two tokens: one with the base64url alphabet, one single-character — the
    # capture is raw and the answer depends only on the token bytes.
    for my $token ('tok-Abc_123', 'x') {
        my $want = $akey_obj->key_authorization($token) . "\n";
        my $raw  = "GET /.well-known/acme-challenge/$token HTTP/1.1\r\nHost: localhost\r\n\r\n";
        my $p = page($pp, $raw);
        my $r = page($rp, $raw);
        is $p->{status}, 200, "perl 200 ($token)";
        is $r->{status}, 200, "rust 200 ($token)";
        is $p->{ct}, $r->{ct}, "the same Content-Type ($token)";
        like $p->{ct}, qr{^text/plain}, "served as text/plain ($token)";
        is $p->{body}, $want, "the perl body IS the key authorization ($token)";
        is $r->{body}, $p->{body}, "the responder body is byte-identical ($token)";
    }

    # A template only matches a path with the same segment count.
    my ($p, $r) = (page($pp, "GET /.well-known/acme-challenge HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                   page($rp, "GET /.well-known/acme-challenge HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    is $p->{status}, 404, 'perl 404 when the challenge template cannot match';
    is $r->{status}, 404, 'rust 404 when the challenge template cannot match';

    kill 'TERM', $pf, $rf;
    waitpid $_, 0 for $pf, $rf;
};

# ── teardown ────────────────────────────────────────────────────────────────
kill 'TERM', $perl_front, $rust_front;
waitpid $_, 0 for $perl_front, $rust_front;

done_testing;
