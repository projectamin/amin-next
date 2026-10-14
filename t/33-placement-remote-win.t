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
        tiers          => [qw(metal-96c metal-32c metal-16c)],
        zones          => [qw(us-east-1 local-zone)],
        netpols        => [qw(vpc-a)],
        max_redundancy => 255,
        vpc_quota      => 4,
        memory_tier    => 1,
        tenant_id      => 't-tenant-remotewin',
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

# Force local tier mismatch → peer-A wins remote
# Mesh: 2 peers. peer-A = tier=metal-96c (req tier match), peer-B = metal-32c mismatch
Amin::Discovery::Mesh->mock_peer_state({
    local_node_id => ("\x11" x 32),
    peer_count    => 2,
    generation    => 1,
    peers => [
        { node_id => ("\xAA" x 32), tier => 'metal-96c', zone => 'local-zone',
          load_pct => 10, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
        { node_id => ("\xBB" x 32), tier => 'metal-32c', zone => 'local-zone',
          load_pct => 30, free_mem_MB => 1_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
    ],
});

# Override local host: tier metal-32c (req metal-96c mismatch), free ssd 0 (<1 GB = ineligible fallback via ssd)
$Amin::Schedule::Placement::_LocalPeerTestOverride = {
    node_id     => ("\x11" x 32),
    tier        => 'metal-32c',         # vs req metal-96c → TIER_MISMATCH
    zone        => 'local-zone',
    load_pct    => 50,
    free_mem_MB => 500,                # vs memory_max 1024 → INELIGIBLE via mem
    free_ssd_GB => 0,                  # vs WORKING_SET_SSD_GB=1 → INELIGIBLE
    hot_refs    => [],
};

my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);

my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024" amin:pids_max="256"/>
  <amin:net amin:vpc="vpc-a"/>
  <amin:exec amin:id="sp1" amin:name="remotetask" amin:tier="metal-96c" amin:zone="local-zone" amin:redundancy="1">
    <amin:argv>/bin/echo</amin:argv><amin:argv>REMOTE_WIN_MARKER_T33_XYZ</amin:argv>
  </amin:exec>
</amin:init>
XML

# ── TR-5.1: StreamCapture placement decision=remote + winner peer=AA ──
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

my ($p_idx, $r_idx, $s_idx);
for my $i (0..$#names) {
    if ($names[$i] eq 'placement' && !defined $p_idx) { $p_idx = $i }
    if ($names[$i] eq 'result'    && !defined $r_idx) { $r_idx = $i }
    if ($names[$i] eq 'status'    && !defined $s_idx) { $s_idx = $i }
}
ok(defined $p_idx, 't33 TR-5.1: placement synthetic present');
SKIP: {
    skip "No placement element", 5 unless defined $p_idx;
    my $pl = $starts[$p_idx][1];
    is(attr_val($pl, 'decision'), 'remote',
        't33 AC-14.3: placement decision=remote (local ineligible peer-A wins)');
    my $peer = attr_val($pl, 'peer') // '';
    ok(length($peer) > 0, 't33 TR-5.1: placement peer attr present (remote node id)');
    like($peer, qr/^aa+$/, 't33 TR-5.1: peer attr matches peer-A node id (all 0xAA)');
    like(attr_val($pl, 'clamped_redundancy') // '', qr/^\d+$/,
        't33 AC-14.10: clamped_redundancy numeric present on placement');
    like(attr_val($pl, 'winner') // '', qr/^[0-9a-f]{64}$/,
        't33 TR-5.1: winner attr is 64-hex node_id');
}

# ── TR-5.2: remote result/status reinjected as SAX ──
SKIP: {
    skip "No result/status elements", 4 unless defined $r_idx && defined $s_idx;
    ok($p_idx < $r_idx, 't33 AC-14.3: placement idx < result idx');
    my $res = $starts[$r_idx][1];
    like(attr_val($res, 'kind') // '', qr/running|done/,
        't33 AC-14.3: result kind is running|done (remote reinjected)');
    my $st = $starts[$s_idx][1];
    is(attr_val($st, 'rc'), '0',
        't33 AC-14.3: <status rc=0 from remote winner terminal');
    like(attr_val($st, 'exit_kind') // '', qr/ok|done/,
        't33 AC-14.3: exit_kind ok (remote success)');
}

# ── TR-5.3: Writer output contains remote marker AND not local marker ──
{
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    like($out, qr/placement[^>]*decision="remote"/,
        't33 AC-14.3: writer contains placement decision=remote');
    like($out, qr/REMOTE_WIN_MARKER_T33_XYZ/,
        't33 AC-14.3: writer contains remote workload marker (reinjected stream bytes)');
    unlike($out, qr/rc="-6144"/,
        't33 TR-5.3: NOT rc=-6144 (remote peer was eligible, dispatched OK');
}

# reset
Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
$Amin::Schedule::Placement::_LocalPeerTestOverride = undef;

done_testing;
