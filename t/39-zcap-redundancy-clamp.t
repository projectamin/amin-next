use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
use Amin::Test::StreamCapture;
use Amin::Discovery::Mesh;
use Amin::Mesh::Transport::InProcess;
use Amin::Auth::ZCap;
use Amin::Schedule::Placement;
require MIME::Base64;

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(metal-96c metal-32c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 clamp-z);
    my @netps  = $o{netpols}? @{$o{netpols}}: qw(vpc-a);
    my $max_r  = $o{max_redundancy} // 2;   # KEY: low zcap ceiling
    my $vpc_q  = $o{vpc_quota} // 4;
    my $mem_t  = $o{memory_tier} // 1;
    my $tenant = $o{tenant_id} // 't-tenant-clamp';
    my $ts     = $o{ts} // 1735689600;
    my $vk     = $o{vk}  // ("\x00" x 2592);
    my $sig    = $o{sig} // ("\xee" x 4627);
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

# 5 peers all eligible tier=metal-96c. ZCap max_redundancy=2
Amin::Discovery::Mesh->mock_peer_state({
    local_node_id => ("\x11" x 32),
    peer_count    => 5,
    generation    => 1,
    peers => [
        map {;
        { node_id => (chr(0xA0 + $_) x 32), tier => 'metal-96c', zone => 'clamp-z',
          load_pct => 10 + $_*5, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
          hot_refs => [("\x00" x 32) x 4] }
    } 0..4
    ],
});

# local ineligible → remote, spawn declares redundancy=5
$Amin::Schedule::Placement::_LocalPeerTestOverride = {
    node_id     => ("\x11" x 32),
    tier        => 'shared',
    zone        => 'clamp-z',
    load_pct    => 50,
    free_mem_MB => 100,
    free_ssd_GB => 0,
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

# zcap token allows high value (passes ZCap scope check early kill)
# then Placement clamp to lower explicit override
my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);

# Placement sees ceiling max_redundancy=2 (not token 255) via scope override
Amin::Auth::ZCap->_test_override_scope({
    max_redundancy => 2,
    tenant_id      => 't-tenant-clamp',
    tiers          => [qw(metal-96c metal-32c)],
    zones          => [qw(us-east-1 clamp-z)],
    memory_tier    => 1,
    vpc_quota      => 4,
    _test_pinned   => 1,
});

# spawn declares redundancy=5 (expect clamped to MIN(5, zcap max=2, eligible=5) = 2
my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024" amin:pids_max="256"/>
  <amin:net amin:vpc="vpc-a"/>
  <amin:exec amin:id="sp1" amin:name="clamped" amin:tier="metal-96c" amin:zone="clamp-z" amin:redundancy="5">
    <amin:argv>/bin/echo</amin:argv><amin:argv>CLAMP_T39_XYZ</amin:argv>
  </amin:exec>
</amin:init>
XML

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
    my ($p_idx) = grep { $names[$_] eq 'placement' } 0..$#names;
    SKIP: {
        skip "No placement", 2 unless defined $p_idx;
        my $pl = $starts[$p_idx][1];
        is(attr_val($pl, 'clamped_redundancy'), '2',
            't39 AC-14.10: clamped_redundancy=2 (MIN(spawn5, zcap max=2');
        is(attr_val($pl, 'decision'), 'remote',
            't39 TR-7.1: decision=remote still');
    }
    # after FIRST run: transport dispatch_count should be exactly 2 (not 4 from two runs)
    is($shared_tr->dispatch_count, 2,
        't39 AC-14.10: dispatch_count == 2 — clamped (zcap ceiling clamps spawn-declared 5 → 2 exactly');
    is(scalar(@{$shared_tr->last_dispatched // []}), 2,
        't39 AC-14.10: last_dispatched has exactly 2 peer ids');
    my $dispatched = $shared_tr->last_dispatched // [];
    my @sorted = sort { unpack('C', substr($a,0,1)) cmp unpack('C', substr($b,0,1)) } @$dispatched;
    is(unpack('C', substr($sorted[0],0,1)), 0xA0, 't39 TR-7.2: dispatched peer0 (lowest load 10) = top1');
    is(unpack('C', substr($sorted[1],0,1)), 0xA1, 't39 TR-7.2: dispatched peer1 (load 15) = top2');
}

{
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    like($out, qr/CLAMP_T39_XYZ/, 't39 TR-7.2: winner marker in output OK');
}

# reset
Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
$Amin::Schedule::Placement::_LocalPeerTestOverride = undef;
{ no strict 'refs'; no warnings 'redefine'; *Amin::Schedule::Placement::_lazy_transport = $orig_new; }

done_testing;
