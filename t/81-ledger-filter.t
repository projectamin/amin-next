#!/usr/bin/env perl
# t/81-ledger-filter.t — audited-event ledger: generic events, billing, settlement,
# per-actor chains, fail-closed commit.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use lib dirname(__FILE__) . '/../perl-lib';
use XML::SAX::Base;
use Encode ();

use Amin qw(NS);
use Amin::ToolPaths;
use Amin::Filter::Ledger;

my $bctool = $ENV{AMIN_BCTOOL} || Amin::ToolPaths::tool_bctool();
plan skip_all => 'bctool not built (cargo build -p bitcache)' unless $bctool && -x $bctool;

my $slab = tempdir(CLEANUP => 1) . '/ledger.slab';

# a sink that records what flows through
{ package Sink; use parent 'XML::SAX::Base';
  sub start_element { push @{$_[0]{seen}}, $_[1]{LocalName}; $_[0]->SUPER::start_element($_[1]) } }

sub el ($ns, $ln, %a) {
    return { NamespaceURI => $ns, LocalName => $ln, Name => $ln, Prefix => '',
        Attributes => { map { ("{}$_" => { Name => $_, LocalName => $_, Prefix => '', NamespaceURI => '', Value => $a{$_} }) } keys %a } };
}
sub run_events ($f, @els) {
    my $sink = bless { seen => [] }, 'Sink';
    $f->set_handler($sink);
    $f->start_document({});
    for my $e (@els) { $f->start_element($e); $f->end_element($e) }
    $f->end_document({});
    return $sink;
}
sub show ($i) {
    my %r;
    for my $l (split /\n/, `$bctool ledger-show --slab $slab --index $i`) {
        my @f = split /\t/, $l, 3;
        if ($f[0] eq 'attr') { $r{"attr:$f[1]"} = Encode::decode('UTF-8', $f[2]) } else { $r{$f[0]} = $f[1] }
    }
    return \%r;
}

my $f = Amin::Filter::Ledger->new(slab_path => $slab, bctool_path => $bctool, actor => 'node-1');
my $LNS = Amin::Filter::Ledger::LEDGER_NS();
my $UCC = do { require Amin::UCC; Amin::UCC::UCC_NS() };

my $sink = run_events($f,
    el(NS(), 'billing', pid => 42, cpu_ms => 1500, rss_kb => 900, tenant_id => 'tenant-a'),
    el($UCC, 'settlement', amount => '12.50', currency => 'USD', finality => 'irrevocable', kind => 'funds-transfer'),
    el($LNS, 'event', kind => 'ai.action', actor => 'agent-7', subject => 'tool:fs.write',
       auth => 'ab' x 32, path => '/etc/passwd', note => "tab\there = odd & ünï"),
    el($LNS, 'event', kind => 'ai.action', actor => 'agent-7', subject => 'tool:net.fetch'),
    el($LNS, 'event', actor => 'x'),                       # malformed (no kind): ignored
    el(NS(), 'other'),
);
is($sink->{seen}, [qw(billing settlement event event event other)], 'stream passes through untouched');

my @r = $f->receipts;
is(scalar @r, 1, 'one batch commit'); is($r[0]{count}, 4, 'four audited events recorded');

my $b = show(0);
is([@$b{qw(kind actor subject seq)}], ['billing','tenant-a','42',1], 'billing → kind billing, actor = tenant');
is($b->{'attr:cpu_ms'}, '1500', 'billing attrs carried');
my $s = show(1);
is([@$s{qw(kind actor subject)}], ['settlement','node-1','funds-transfer'], 'settlement → kind settlement, default actor');
is($s->{'attr:amount'}, '12.50', 'settlement amount carried');
my $a1 = show(2);
is([@$a1{qw(kind actor subject seq)}], ['ai.action','agent-7','tool:fs.write',1], 'generic event');
is($a1->{auth}, 'ab' x 32, 'auth reference recorded');
is($a1->{'attr:note'}, "tab\there = odd & ünï", 'awkward bytes survive escaping');
my $a2 = show(3);
is($a2->{seq}, 2, 'second agent-7 event continues the agent-7 chain');
is($a2->{prev}, $a1->{id}, '… linked to the previous agent-7 entry');

# a second filter instance continues the same chains and gives a verifiable head
my $g = Amin::Filter::Ledger->new(slab_path => $slab, bctool_path => $bctool, actor => 'node-1');
run_events($g, el($LNS, 'event', kind => 'ai.action', actor => 'agent-7', subject => 'again'));
is(show(4)->{seq}, 3, 'chain continues across filter instances');
my $v = `$bctool ledger-verify --slab $slab`; is($? >> 8, 0, 'ledger-verify OK'); like($v, qr/OK/, 'verify output');

# batching: more events than batch_max → several commits, one fsync each
my $h = Amin::Filter::Ledger->new(slab_path => $slab, bctool_path => $bctool, actor => 'n', batch_max => 3);
run_events($h, map { el($LNS, 'event', kind => 'tick', subject => "t$_") } 1..7);
is([map { $_->{count} } $h->receipts], [3,3,1], 'batched 3+3+1');

# long-lived writer: one bctool process across several batches, chains intact
{
    my $st = Amin::Filter::Ledger->new(slab_path => $slab, bctool_path => $bctool, actor => 'n', batch_max => 3, stream => 1);
    run_events($st, map { el($LNS, 'event', kind => 'ai.action', actor => 'agent-9', subject => "s$_") } 1..7);
    is([map { $_->{count} } $st->receipts], [3,3,1], 'stream: batched 3+3+1 on one process');
    ok(!$st->_h, 'stream closed at end_document (slab lock released)');
    my @sz = map { $_->{size} } $st->receipts;
    is($sz[2] - $sz[0], 4, 'stream: receipts advance the same log');
    my $v2 = `$bctool ledger-verify --slab $slab`; is($? >> 8, 0, 'stream: ledger-verify OK');
    my $bad = Amin::Filter::Ledger->new(slab_path => $slab, bctool_path => $bctool, stream => 1);
}

# ucc:event + emitter helper
{
    require Amin::Ledger::Event;
    my $e = Amin::Filter::Ledger->new(slab_path => $slab, bctool_path => $bctool, actor => 'node-1');
    my $before = (split /\t/, (grep { /^size/ } split /\n/, `$bctool ledger-verify --slab $slab`)[0])[1];
    $e->set_handler(bless { seen => [] }, 'Sink');
    $e->start_document({});
    $e->start_element(el($UCC, 'event', maker => 'maker-1', article => 'art-9', kind => 'filed'));
    Amin::Ledger::Event::emit_authz($e, decision => 'deny', actor => 'agent-3', action => 'fs.write', reason => 'no cap');
    Amin::Ledger::Event::emit_tool_call($e, agent => 'agent-3', tool => 'net.fetch', model => 'm1');
    $e->end_document({});
    my $n = $before;
    my @k = map { show($n + $_) } 0..2;
    is([map { $_->{kind} } @k], ['ucc.event','authz.deny','ai.tool_call'], 'ucc:event and emitter kinds recorded');
    is($k[0]{actor}, 'maker-1', 'ucc:event actor = maker'); is($k[0]{subject}, 'art-9', 'ucc:event subject = article');
    is($k[1]{'attr:reason'}, 'no cap', 'authz reason carried');
    like(dies { Amin::Ledger::Event::emit_authz($e, decision => 'maybe') }, qr/grant or deny/, 'authz validates decision');
}

# fail closed: an unrecordable audited event aborts the stream
my $bad = Amin::Filter::Ledger->new(slab_path => '/nonexistent-dir/x.slab', bctool_path => $bctool);
like(dies { run_events($bad, el($LNS, 'event', kind => 'k')) }, qr/could not record 1 audited event/, 'commit failure is fatal');
my $nocfg = Amin::Filter::Ledger->new(bctool_path => $bctool);
local $ENV{AMIN_LEDGER_SLAB};
like(dies { run_events($nocfg, el($LNS, 'event', kind => 'k')) }, qr/no ledger slab configured/, 'no slab configured is fatal');

done_testing;
