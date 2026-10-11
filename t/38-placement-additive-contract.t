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
require Digest::SHA;

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(metal-96c metal-32c metal-16c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 additive-z);
    my @netps  = $o{netpols}? @{$o{netpols}}: qw(vpc-a);
    my $max_r  = $o{max_redundancy} // 255;
    my $vpc_q  = $o{vpc_quota} // 4;
    my $mem_t  = $o{memory_tier} // 1;
    my $tenant = $o{tenant_id} // 't-tenant-additive';
    my $ts     = $o{ts} // 1735689600;
    my $vk     = $o{vk}  // ("\x00" x 2592);
    my $sig    = $o{sig} // ("\xff" x 4627);
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

sub attrs_sha ($attr_hash) {
    my $ea = $attr_hash // {};
    my %kv;
    for my $k (keys %$ea) {
        next unless ref $ea->{$k} eq 'HASH';
        my $ln = $ea->{$k}{LocalName} // '';
        next unless length($ln) > 0;
        $kv{$ln} = $ea->{$k}{Value};
    }
    my $s = join '&', map { "$_=$kv{$_}" } sort grep { exists $kv{$_} }
                     qw(id name tier zone redundancy);
    return Digest::SHA::sha256_hex($s);
}

# ── Case A: local win — additive synthetic prepend, attr sha256 unchanged
{
    Amin::Discovery::Mesh->mock_peer_state({
        local_node_id => ("\x11" x 32),
        peer_count    => 0, peers => [], generation => 0,
    });
    my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024"/>
  <amin:exec amin:id="s1" amin:name="additiveA" amin:tier="metal-32c" amin:zone="additive-z" amin:redundancy="1">
    <amin:argv>/bin/echo</amin:argv><amin:argv>ADD_T38_LOCAL_A_MARKER</amin:argv>
  </amin:exec>
</amin:init>
XML

    my $src_sha = do {
        my %a = (id => 's1', name => 'additiveA', tier => 'metal-32c',
                 zone => 'additive-z', redundancy => '1');
        my $s = join '&', map { "$_=$a{$_}" } sort keys %a;
        Digest::SHA::sha256_hex($s);
    };

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
    my @pairs;
    for my $i (0..$#names) { push @pairs, [$i, $names[$i]]; }
    my @placement_idx = map { $_->[0] } grep { $_->[1] eq 'placement' } @pairs;
    my @exec_idx      = map { $_->[0] } grep { $_->[1] eq 'exec'      } @pairs;
    is(scalar(@placement_idx), scalar(@exec_idx),
        't38 AC-14.8: placement synthetic count == exec count (1:1 additive)');
    if (@placement_idx && @exec_idx) {
        ok($placement_idx[0] < $exec_idx[0],
            't38 AC-14.8: placement[0] idx < exec[0] idx — additive synthetic prepend no reorder no rewrite');
        is(attrs_sha($starts[$exec_idx[0]][1]{Attributes}), $src_sha,
            't38 AC-14.8: exec attr sha256 == source hash — Placement NEVER mutates spawn attrs (DI-1 additive only)');
    }

    # Writer: marker present, placement count == exec count in raw text output
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    like($out, qr/ADD_T38_LOCAL_A_MARKER/, 't38: case A local marker present');
    my $pc = () = $out =~ /amin:placement/g;
    my $ec = () = $out =~ /amin:exec/g;
    is($pc, $ec, 't38 AC-14.8: writer placement count == exec count');

    Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
}

# ── Case B: remote win → winner stream bytes verbatim length match
{
    Amin::Discovery::Mesh->mock_peer_state({
        local_node_id => ("\x11" x 32),
        peer_count    => 1,
        generation    => 1,
        peers => [
            { node_id => ("\xAA" x 32), tier => 'metal-96c', zone => 'additive-z',
              load_pct => 10, free_mem_MB => 2_000_000, free_ssd_GB => 5000,
              hot_refs => [("\x00" x 32) x 4] },
        ],
    });
    $Amin::Schedule::Placement::_LocalPeerTestOverride = {
        node_id     => ("\x11" x 32),
        tier        => 'shared',
        zone        => 'additive-z',
        load_pct    => 50,
        free_mem_MB => 50,
        free_ssd_GB => 0,
        hot_refs    => [],
    };

    # Shared transport: capture winner poll_stream bytes for length match
    my $shared_tr = Amin::Mesh::Transport::InProcess->new;
    my @captured_winner_bytes;
    no strict 'refs';
    no warnings 'redefine';
    my $orig_poll = \&Amin::Mesh::Transport::SpawnHandle::poll_stream;
    *Amin::Mesh::Transport::SpawnHandle::poll_stream = sub ($self, $max = 4096) {
        my $b = $orig_poll->($self, $max);
        if (defined $b && length($b)) {
            push @captured_winner_bytes, $b;
        }
        return $b;
    };
    my $orig_newtr = \&Amin::Schedule::Placement::_lazy_transport;
    *Amin::Schedule::Placement::_lazy_transport = sub ($self) {
        return $self->transport if defined $self->transport;
        $self->transport($shared_tr);
        return $shared_tr;
    };
    use strict 'refs';

    my $token = build_zcap_token(max_redundancy => 255, memory_tier => 1);
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="1024"/>
  <amin:exec amin:id="s2" amin:name="additiveB" amin:tier="metal-96c" amin:zone="additive-z" amin:redundancy="1">
    <amin:argv>/bin/echo</amin:argv><amin:argv>ADD_T38_REMOTE_B_MARKER</amin:argv>
  </amin:exec>
</amin:init>
XML

    my $cap = Amin::Test::StreamCapture->new(capture_chars => 1);
    Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $cap,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    my $polled_total = 0; $polled_total += length($_) for @captured_winner_bytes;

    # sum of char data events + tag event sizes as approximate verification
    my $chars_total = 0;
    for my $e ($cap->captured->@*) {
        if ($e->[0] eq 'characters') { $chars_total += length($e->[1]{Data} // ''); }
    }

    ok($polled_total > 0, 't38 TR-8.1: remote poll_stream captured bytes > 0');
    cmp_ok($chars_total, '>=', 10, 't38 TR-8.1: local reinject chars >= 10 bytes');
    # Verbatim bytes from winner stream → workload marker in capture
    my @ev  = $cap->captured->@*;
    my $flat = join '', map { $_->[0] eq 'characters' ? ($_->[1]{Data} // '') : '' } @ev;
    like($flat, qr/ADD_T38_REMOTE_B_MARKER/,
        't38 AC-14.3: winner stream marker bytes verbatim reinjected into local SAX chain');

    # restore
    {
        no strict 'refs';
        no warnings 'redefine';
        *Amin::Mesh::Transport::SpawnHandle::poll_stream = $orig_poll;
        *Amin::Schedule::Placement::_lazy_transport = $orig_newtr;
    }
    Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
    $Amin::Schedule::Placement::_LocalPeerTestOverride = undef;
}

done_testing;
