#!/usr/bin/env perl
# Streaming responses (plan §4.8).
#
# render_stream returns a PSGI streaming coderef: the server calls it with a
# responder, calling that responder commits the status line, and every chunk
# after goes straight to the socket.  Three properties matter and are easy to
# get wrong:
#
#   1. The status latch fires EXACTLY ONCE.  Committing twice means a second
#      status line on an already-open response.
#   2. The body arrives as MANY chunks, not one blob — otherwise it is
#      buffering wearing a streaming costume, and O(page) memory again.
#   3. Reassembling the chunks must give the same well-formed document the
#      buffered path produces.
#
# A fake responder/writer stands in for the server so this runs without a
# socket; t/57 exercises the real Starman path over TCP.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::AXA::PSGI;
use Amin::AXA::App;
use Amin::AXA::Store;
use Amin::AXA::Store::SQLite;
use Amin::Handler::HTML;

my $ROOT = path(dirname(__FILE__))->parent->absolute;

# stand-in for the server-supplied writer
{
    package Axat::FakeWriter;
    sub new ($class, %o) { bless { writes => [], closed => 0, %o }, $class }
    sub write ($self, $chunk) { push @{ $self->{writes} }, $chunk; return }
    sub close ($self) { $self->{closed} = 1; return }
    sub chunks ($self) { $self->{writes} }
    sub joined ($self) { join '', @{ $self->{writes} } }
    sub closed ($self) { $self->{closed} }
}

my $have_sqlite = eval { require DBI; require DBD::SQLite; 1 };

# ── app + spec, wired the same way bin/amin wires them ──────────────────
my $store = $have_sqlite
    ? Amin::AXA::Store::SQLite->new(path => '' . $ROOT . '/.cache/t56-store.sqlite')
    : Amin::AXA::Store->new;
unlink '' . $ROOT . '/.cache/t56-store.sqlite';
Amin::AXA::Store->set_default($store);

my $app = Amin::AXA::App->load("$ROOT/examples/apps/shop-ui");
Amin::AXA::App->set_default($app);

my $spec = Amin::Machine::MachineSpec->new->spec;
push $spec->{filters}->@*, (
    { class => 'Amin::Example::Shop', meta => { position => 'late',
        element => 'request', namespace => 'urn:projectamin:example:shop',
        permissions => '' } },
);

sub stream_of {
    my ($path, $extra) = @_;
    my $r = $app->get_route($path) or die "no route for $path";
    return Amin::AXA::PSGI->render_stream(
        $spec, $r->{fragment},
        { sid => 's1', csrf => 'tok' }, $extra // []);
}

# ── 1. the latch fires exactly once ─────────────────────────────────────
my (@committed, $W);
my $responder = sub {
    my $hdr = shift;
    push @committed, $hdr;
    $W = Axat::FakeWriter->new;
    return $W;
};

my $stream = stream_of('/');
is(ref $stream, 'CODE', 'render_stream returns a PSGI streaming coderef');

$stream->($responder);
is(scalar @committed, 1, 'status latch fired exactly once (not per chunk)');
is($committed[0][0], 200, 'committed status is 200');
ok(!grep { lc($_) eq 'content-length' } @{ $committed[0][1] },
   'no Content-Length on a streamed response (server uses chunked)');

# ── 2. many chunks, not one blob ────────────────────────────────────────
my $n = scalar @{ $W->chunks };
cmp_ok($n, '>', 1, "body arrived as $n separate chunks, not one buffer");

ok($W->closed, 'writer was closed at the end of the stream');

# ── 3. reassembly matches the buffered path ─────────────────────────────
my $streamed = $W->joined;
my $buffered = Amin::AXA::PSGI->render(
    $spec, $app->get_route('/')->{fragment}, { sid => 's1', csrf => 'tok' });
my $buffered_html = ref $buffered->[2] eq 'ARRAY' ? $buffered->[2][0] : '';

like($streamed, qr{^<!DOCTYPE html>}, 'streamed body starts with the doctype');
like($streamed, qr{</html>\s*\z},    'streamed body ends with </html>');
is($streamed, $buffered_html, 'streamed bytes are identical to the buffered path');
is(length($streamed), length($buffered_html), '  same length — nothing dropped at the boundaries');

# ── cookie headers threaded in BEFORE the latch ─────────────────────────
my @with_cookie;
my $resp2 = sub { push @with_cookie, shift; return Axat::FakeWriter->new };
stream_of('/', ['Set-Cookie' => 'axa_sid=test; Path=/'])->($resp2);
# PSGI headers are a FLAT key/value list, so scan every other element.
my @hdrs = @{ $with_cookie[0][1] };
my $found_cookie = 0;
for (my $i = 0; $i < @hdrs; $i += 2) {
    $found_cookie = 1 if lc($hdrs[$i] // '') eq 'set-cookie';
}
ok($found_cookie, 'Set-Cookie is present on the latched headers (too late to add afterwards)')
    or diag 'latched headers: ' . join(', ', @hdrs);

# ── a fragment that emits nothing still gets a response ─────────────────
# start_document always emits the doctype, so this is belt-and-braces; but a
# silent socket is far worse than an empty page if a future handler regresses.
my (@empty_committed, $EW);
my $resp3 = sub { push @empty_committed, shift; $EW = Axat::FakeWriter->new; return $EW };
my $empty = Amin::AXA::PSGI->render_stream(
    $spec, '<shop:request xmlns:shop="urn:projectamin:example:shop"/>',
    { sid => 's', csrf => 't' }, []);
$empty->($resp3);
is(scalar @empty_committed, 1, 'an empty fragment still commits exactly one response');
is($empty_committed[0][0], 200, '  and it is a 200, not a silent socket');

# ── a mid-stream failure must not emit a second status line ─────────────
# Note what actually happens, verified rather than assumed: start_document
# emits the doctype FIRST, so the latch has already committed 200 by the time
# a fragment-level parse error surfaces.  A fragment error therefore yields a
# truncated 200, not a 500 — that is inherent to streaming, and the invariant
# that protects the client is "exactly one status line, then close".
my (@err_committed, $ErrW);
my $resp4 = sub { push @err_committed, shift; $ErrW = Axat::FakeWriter->new; return $ErrW };
my $bad = Amin::AXA::PSGI->render_stream(
    $spec, '<shop:request xmlns:shop="urn:projectamin:example:shop"><unclosed>',
    { sid => 's', csrf => 't' }, []);
$bad->($resp4);
is(scalar @err_committed, 1, 'a failing fragment commits exactly ONE response');
is($err_committed[0][0], 200, '  and it is the latched 200 (doctype emits before the error)');
ok($ErrW->closed, '  the stream is closed rather than left hanging');
ok(!grep { lc($_) eq 'content-length' } @{ $err_committed[0][1] },
   '  with no Content-Length, so a truncated body is detectable by the client');

# ── the sink: streaming must not accumulate ─────────────────────────────
my @got;
my $h = Amin::Handler::HTML->new(sink => sub { push @got, $_[0] });
$h->start_document;
$h->start_element({ NamespaceURI => 'http://www.w3.org/1999/xhtml',
                    LocalName => 'p', Attributes => {} });
$h->characters({ Data => 'hi' });
$h->end_element({ NamespaceURI => 'http://www.w3.org/1999/xhtml', LocalName => 'p' });
ok(scalar @got > 1, 'handler sink is called per event');
is($h->output, '', 'buffered buf stays empty when streaming (O(1) memory)');
# the serializer emits a newline after each opening tag, so <p> is its own chunk
is(join('', @got), "<!DOCTYPE html>\n<p>\nhi</p>\n", '  and the sink saw the full document');

# buffered mode still works with no sink
my $h2 = Amin::Handler::HTML->new;
$h2->start_document;
is($h2->output, "<!DOCTYPE html>\n", 'no sink -> buffered output still accumulates');

$store->can('disconnect') and $store->disconnect;
unlink '' . $ROOT . '/.cache/t56-store.sqlite';

done_testing;
