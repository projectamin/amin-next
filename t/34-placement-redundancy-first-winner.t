use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
use Amin::Test::StreamCapture;
use Amin::Discovery::Mesh;
use Amin::Mesh::Transport::InProcess;
use Amin::Schedule::Placement;
require MIME::Base64;

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(metal-96c metal-32c metal-16c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 t33-zone);
    my @netps  = $o{netpols}? @{$o{netpols}}: qw(vpc-a);
    my $max_r  = $o{max_redundancy} // 255;
    my $vpc_q  = $o{vpc_quota} // 4;
    my $mem_t  = $o{memory_tier} // 1;
    my $tenant = $o{tenant_id} // 't-tenant-redundancy';
    my $ts     = $o{ts} // 1735689600;
    my $vk     = $o{vk}  // ("\x00" x 2592);
    my $sig    = $o{sig} // ("\xcc" x 4627);
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

# ── Mock mesh: 3 peers, all tier=metal-96c eligible, same zone, varying loads
Amin::Discovery::Mesh->mock_peer_state({
    local_node_id => ("\x11" x 32),
    peer_count    => 3,
    generation    => 1,
    peers => [
        { node_id => ("\xAA" x 32), tier => 'metal-96c', zone => 't33-zone',
          load_pct => 10, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
        { node_id => ("\xBB" x 32), tier => 'metal-96c', zone => 't33-zone',
          load_pct => 20, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
        { node_id => ("\xCC" x 32), tier => 'metal-96c', zone => 't33-zone',
          load_pct => 30, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] },
    ],
});

# Local: ineligible → remote forced
$Amin::Schedule::Placement::_LocalPeerTestOverride = {
    node_id     => ("\x11" x 32),
    tier        => 'metal-32c',
    zone        => 't33-zone',
    load_pct    => 50,
    free_mem_MB => 100,
    free_ssd_GB => 0,
    hot_refs    => [],
};

my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);

# Build a shared transport instance so we can inspect cancel_count
my $shared_tr = Amin::Mesh::Transport::InProcess->new;
# Inject shared transport into Placement via package-scope hook
no strict 'refs';
no warnings 'redefine';
my $orig_new = \&Amin::Schedule::Placement::_lazy_transport;
*Amin::Schedule::Placement::_lazy_transport = sub ($self) {
    return $self->transport if defined $self->transport;
    $self->transport($shared_tr);
    return $shared_tr;
};
use strict 'refs';

my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024" amin:pids_max="256"/>
  <amin:net amin:vpc="vpc-a"/>
  <amin:exec amin:id="sp1" amin:name="redtask" amin:tier="metal-96c" amin:zone="t33-zone" amin:redundancy="3">
    <amin:argv>/bin/echo</amin:argv><amin:argv>REDUNDANCY_WIN_T34_XYZ</amin:argv>
  </amin:exec>
</amin:init>
XML

# ── TR-5.4: N=3 dispatch, 1 winner, cancel_count == 2 ──
{
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
        filter_args => { 'Amin::Schedule::Placement' => {
            _explicit_local_for_test => 1,
        }},
    );

    is($shared_tr->dispatch_count, 3,
        't34 AC-14.4: dispatch_count == 3 (N=3 redundancy dispatched)');
    is($shared_tr->cancel_count // 0, 2,
        't34 AC-14.4: cancel_count == 2 (first-winner cancels losers)');
    is(scalar(@{$shared_tr->last_dispatched // []}), 3,
        't34 TR-5.4: last_dispatched had 3 peer ids');

    like($out, qr/REDUNDANCY_WIN_T34_XYZ/,
        't34 TR-5.4: workload marker present in output (winner reinjected)');
    # only 1 result/status pair in capture
    my @status  = ($out =~ m{<amin:status\s}g);
    cmp_ok(scalar(@status), '>=', 1, 't34 TR-5.4: at least 1 <status> element');
    like($out, qr/placement[^>]*clamped_redundancy="3"/,
        't34 AC-14.10: clamped_redundancy=3 (zcap max 255 allows 3)');
    # winner should be peer-aa (lowest load 10 → lowest score)
    like($out, qr/placement[^>]*peer="[a-f0-9]{64}"/, 't34 TR-5.4: winner peer attr present');
}

# cleanup state
Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
$Amin::Schedule::Placement::_LocalPeerTestOverride = undef;
# restore original _lazy_transport
{
    no strict 'refs';
    no warnings 'redefine';
    *Amin::Schedule::Placement::_lazy_transport = $orig_new;
}

done_testing;
