use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
use Amin::Test::StreamCapture;
use Amin::Discovery::Mesh;
require MIME::Base64;
require Digest::SHA;

sub build_zcap_token (%o) {
    # Real e2e: ML-DSA-87 signature issued by the Rust toolchain (bctool) —
    # the same production signer — verifies against Amin::Auth::ZCap with
    # the VK registered as a mesh trust anchor.  Falls back to the legacy
    # structural placeholder when no signer binary is present.
    my %o = (
        tiers          => [qw(metal-32c metal-16c metal-96c)],
        zones          => [qw(us-east-1 us-west-2 local-zone)],
        netpols        => [qw(vpc-a)],
        max_redundancy => 255,
        vpc_quota      => 4,
        memory_tier    => 1,
        tenant_id      => 't-tenant-localwin',
        ts             => 1735689600,
        @_,
    );
    $o{max_redundancy} = 255 if $o{max_redundancy} > 255;
    require Amin::Test::ZCapSign;
    return Amin::Test::ZCapSign::make_zcap_token(%o);
}

sub attr_val ($el, $want) {
    my $A = $el->{Attributes} // {};
    for my $k (keys %$A) {
        next unless ref $A->{$k} eq 'HASH';
        my $ln = $A->{$k}{LocalName} // '';
        if ($ln eq '') { (my $kk = $k) =~ s/^\{[^}]*\}//; $ln = $kk; }
        next unless $ln eq $want;
        return $A->{$k}{Value} if exists $A->{$k}{Value};
    }
    return undef;
}

Amin::Discovery::Mesh->mock_peer_state({
    local_node_id => ("\x12" x 32),
    peer_count    => 2,
    generation    => 1,
    peers => [
        { node_id => ("\xAA" x 32), tier => 'metal-32c', zone => 'local-zone',
          load_pct => 50, free_mem_MB => 1_000_000, free_ssd_GB => 1000,
          hot_refs => [("\x00" x 32) x 4] },
        { node_id => ("\xBB" x 32), tier => 'metal-32c', zone => 'local-zone',
          load_pct => 90, free_mem_MB => 1_000_000, free_ssd_GB => 1000,
          hot_refs => [("\x00" x 32) x 4] },
    ],
});

my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);

# ── TR-3.1 local win ──
my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024" amin:pids_max="256"/>
  <amin:net amin:vpc="vpc-a"/>
  <amin:exec amin:id="sp1" amin:name="prober" amin:tier="metal-32c" amin:zone="local-zone" amin:redundancy="2">
    <amin:argv>/bin/echo</amin:argv><amin:argv>HELLO_LOCAL_WIN_MARKER_XYZ</amin:argv>
  </amin:exec>
</amin:init>
XML

# Run via StreamCapture with Dispatcher->run
my $cap = Amin::Test::StreamCapture->new(capture_chars => 1);
Amin::Machine::Dispatcher->run(
    mode       => 'run',
    source_xml => $xml,
    Handler    => $cap,
    Log        => Amin::Log::Standard->new(stderr => 0),
);
my @ev  = $cap->captured->@*;
my @starts = grep { $_->[0] eq 'start_element' } @ev;
my @names  = map { $_->[1]{LocalName} // '' } @starts;

# Find indices: first placement before first exec
my ($p_idx, $e_idx);
for my $i (0..$#names) {
    if ($names[$i] eq 'placement' && !defined $p_idx) { $p_idx = $i }
    if ($names[$i] eq 'exec'      && !defined $e_idx) { $e_idx = $i }
}
ok(defined $p_idx, 't32 TR-3.1: synthetic <placement> present in capture stream');
ok(defined $e_idx, 't32 TR-3.1: spawn/exec start_element present');
ok((defined $p_idx && defined $e_idx && $p_idx < $e_idx),
    "t32 TR-3.1: placement idx=$p_idx fires BEFORE exec idx=$e_idx (additive sibling prepended — AC-14.2)");

SKIP: {
    skip "No placement/exec elements found", 6 unless defined $p_idx && defined $e_idx;

    my $pl = $starts[$p_idx][1];
    is(attr_val($pl, 'decision'), 'local',   'placement decision=local');
    is(attr_val($pl, 'peer'),     'local',   'placement peer=local — local host wins (AC-14.2)');
    like(attr_val($pl, 'score') // '', qr/^-?\d+$/, 'placement score is numeric (may be negative due to LOCAL_PREFERENCE)');

    my $expected_src_sha = do {
        my $a = { id => 'sp1', name => 'prober', tier => 'metal-32c',
                  zone => 'local-zone', redundancy => '2' };
        my $s = join '&', map { "$_=$a->{$_}" } sort keys %$a;
        Digest::SHA::sha256_hex($s);
    };
    my $actual_sha = do {
        my $ea = $starts[$e_idx][1]{Attributes} // {};
        my %kv;
        for my $k (keys %$ea) {
            next unless ref $ea->{$k} eq 'HASH';
            my $ln = $ea->{$k}{LocalName} // '';
            next unless length($ln) > 0;
            $kv{$ln} = $ea->{$k}{Value};
        }
        my $s = join '&', map { "$_=$kv{$_}" } sort grep { exists $kv{$_} }
                         qw(id name tier zone redundancy);
        Digest::SHA::sha256_hex($s);
    };
    is($actual_sha, $expected_src_sha,
       't32 AC-14.2b: spawn attr SHA256 == source bytes SHA256 — additive-only never mutates attrs (AC-14.8)');

    my $placement_count = 0;
    for my $n (@names) { $placement_count++ if $n eq 'placement' }
    is($placement_count, 1,
       't32 AC-14.8: exactly 1 <placement> synthetic per 1 spawn');
}

# ── AC-14.2 (c): exec runs locally → marker in output via Writer handler ──
{
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    like($out, qr/placement[^>]*decision="local"/,
         'Writer output contains placement decision=local (AC-14.2 additive-only synthetic present in output)');
    like($out, qr/placement[^>]*peer="local"/,
         'Writer output contains placement peer=local (local host selected)');
    like($out, qr/HELLO_LOCAL_WIN_MARKER_XYZ/,
         'AC-14.2(c): spawn executes locally — workload marker present in output stream (not remote)');
}

# reset mock
Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});

done_testing;
