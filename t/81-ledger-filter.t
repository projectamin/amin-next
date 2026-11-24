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

# fail closed: an unrecordable audited event aborts the stream
my $bad = Amin::Filter::Ledger->new(slab_path => '/nonexistent-dir/x.slab', bctool_path => $bctool);
like(dies { run_events($bad, el($LNS, 'event', kind => 'k')) }, qr/could not record 1 audited event/, 'commit failure is fatal');
my $nocfg = Amin::Filter::Ledger->new(bctool_path => $bctool);
local $ENV{AMIN_LEDGER_SLAB};
like(dies { run_events($nocfg, el($LNS, 'event', kind => 'k')) }, qr/no ledger slab configured/, 'no slab configured is fatal');

done_testing;
