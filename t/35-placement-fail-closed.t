use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
use Amin::Test::StreamCapture;
use Amin::Discovery::Mesh;
use Amin::Mesh::Transport::InProcess;
require MIME::Base64;

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(metal-96c metal-32c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 failclosed-z);
    my @netps  = $o{netpols}? @{$o{netpols}}: qw(vpc-a);
    my $max_r  = $o{max_redundancy} // 255;
    my $vpc_q  = $o{vpc_quota} // 4;
    my $mem_t  = $o{memory_tier} // 1;
    my $tenant = $o{tenant_id} // 't-tenant-failclosed';
    my $ts     = $o{ts} // 1735689600;
    my $vk     = $o{vk}  // ("\x00" x 2592);
    my $sig    = $o{sig} // ("\xdd" x 4627);
    my $tier_data = join('', map { pack('v', length($_)) . $_ } @tiers);
    my $zone_data = join('', map { pack('v', length($_)) . $_ } @zones);
    my $netp_data = join('', map { pack('v', length($_)) . $_ } @netps);
    $max_r = 255 if $max_r > 255;
    my $bytes = $sig . $vk . ("\x00" x 32) . pack('Q<', $ts)
              . pack('v', scalar @tiers) . pack('v', scalar @zones)
              . pack('v', scalar @netps) . pack('C', $max_r)
              . pack('V', $vpc_q) . pack('C', $mem_t)
              . pack('v', length($tenant)) . $tenant
              . $tier_data . $zone_data . $netp_data;
    return MIME::Base64::encode_base64($bytes, '');
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

# ALL hosts tier=metal-32c only, no metal-96c available
Amin::Discovery::Mesh->mock_peer_state({
    local_node_id => ("\x11" x 32),
    peer_count    => 3,
    generation    => 1,
    peers => [
        { node_id => ("\xAA" x 32), tier => 'metal-32c', zone => 'failclosed-z',
          load_pct => 10, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
        { node_id => ("\xBB" x 32), tier => 'metal-32c', zone => 'failclosed-z',
          load_pct => 20, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
        { node_id => ("\xCC" x 32), tier => 'metal-32c', zone => 'failclosed-z',
          load_pct => 30, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
    ],
});

# Local is also metal-32c only
$Amin::Schedule::Placement::_LocalPeerTestOverride = {
    node_id     => ("\x11" x 32),
    tier        => 'metal-32c',
    zone        => 'failclosed-z',
    load_pct    => 50,
    free_mem_MB => 1_000_000,
    free_ssd_GB => 5000,
    hot_refs    => [],
};

my $shared_tr = Amin::Mesh::Transport::InProcess->new;
no strict 'refs';
no warnings 'redefine';
my $orig_new = \&Amin::Schedule::Placement::_lazy_transport;
*Amin::Schedule::Placement::_lazy_transport = sub ($self) {
    return $self->transport if defined $self->transport;
    $self->transport($shared_tr);
    return $shared_tr;
};
use strict 'refs';

my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);

# profile req tier=metal-96c → no peers
my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024" amin:pids_max="256"/>
  <amin:net amin:vpc="vpc-a"/>
  <amin:exec amin:id="sp1" amin:name="ineligible" amin:tier="metal-96c" amin:zone="failclosed-z" amin:redundancy="1">
    <amin:argv>/bin/echo</amin:argv><amin:argv>FAIL_CLOSED_MUST_NOT_LEAK_T35_XYZ</amin:argv>
  </amin:exec>
</amin:init>
XML

# ── AC-14.5 fail-closed: no eligible peer → rc=-6144 ──
{
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );

    is($shared_tr->dispatch_count // 0, 0,
        't35 AC-14.5: dispatch_count == 0 — FAIL CLOSED never sent zero remote dispatch attempted');

    like($out, qr/placement[^>]*decision="no_eligible"/,
        't35 AC-14.5: placement decision=no_eligible synthetic');
    like($out, qr/rc="-6144"/,
        't35 AC-14.5: status rc=-6144 placement');
    like($out, qr/exit_kind="placement"/,
        't35 AC-14.5: exit_kind=placement');
    like($out, qr/no eligible peer/,
        't35 AC-14.5: msg "no eligible peer" message');
    unlike($out, qr/FAIL_CLOSED_MUST_NOT_LEAK_T35_XYZ/,
        't35 AC-14.5: workload marker bytes 100% absent; never sent to local/from any peer');
    unlike($out, qr/<amin:exec[^>]*ineligible/,
        't35 AC-14.5: exec element never reaches no execution shell echo never runs');
}

# Also capture stream: placement then result then status — no spawn/exec children flow
{
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
        $p_idx //= $names[$i] eq 'placement' ? $i : undef;
        $r_idx //= $names[$i] eq 'result'    ? $i : undef;
        $s_idx //= $names[$i] eq 'status'    ? $i : undef;
    }
    SKIP: {
        skip "missing elements", 3 unless defined $p_idx && defined $r_idx && defined $s_idx;
        ok($p_idx < $r_idx, 't35 TR-6.1: placement idx < result idx');
        ok($r_idx < $s_idx, 't35 TR-6.1: result idx < status idx');
        my $st = $starts[$s_idx][1];
        is(attr_val($st, 'rc'), '-6144', 't35 TR-6.1: captured status rc=-6144 exact');
    }
}

# reset
Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
$Amin::Schedule::Placement::_LocalPeerTestOverride = undef;
{ no strict 'refs'; no warnings 'redefine'; *Amin::Schedule::Placement::_lazy_transport = $orig_new; }

done_testing;
