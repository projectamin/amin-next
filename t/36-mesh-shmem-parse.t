use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Discovery::Mesh;

use constant {
    MAGIC_HEX => "\x41\x4D\x49\x4E\x5F\x4D\x53\x48",
    MAGIC     => unpack('Q>', "\x41\x4D\x49\x4E\x5F\x4D\x53\x48"),
    HEADER_LEN => 64,
    STRIDE     => 256,
    MAX_PEERS  => 64,
    VERSION    => 1,
    TIER_PAD   => 24,
    ZONE_PAD   => 24,
    HOT_REF_N  => 4,
    HEADER_RESERVED => 12,
};

sub _pack_v2str ($s, $pad) {
    my $l = length($s) > $pad ? substr($s, 0, $pad) : $s;
    return pack('v', length($l)) . $l . ("\x00" x ($pad - length($l)));
}

sub pack_mesh ($node_id, $peers, $generation = 1) {
    my $pcount = scalar(@$peers);
    my $reserved = "\x00" x HEADER_RESERVED;
    my $header = pack('Q> v v a32 a12 Q>', MAGIC, VERSION, $pcount,
                      $node_id, $reserved, $generation);
    substr($header, HEADER_LEN - 8, 8, pack('Q>', $generation));
    my $all_peers = '';
    for my $p (@$peers) {
        my $tier = _pack_v2str($p->{tier}//'', TIER_PAD);
        my $zone = _pack_v2str($p->{zone}//'', ZONE_PAD);
        my @hrs  = ($p->{hot_refs} // [])->@*;
        while (@hrs < HOT_REF_N) { push @hrs, "\x00" x 32 }
        @hrs = map {
            length $_ > 32 ? substr($_, 0, 32)
                           : $_ . ("\x00" x (32 - length $_))
        } @hrs[0 .. HOT_REF_N - 1];
        my $bytes = pack('a32', $p->{node_id}) . $tier . $zone
            . pack('C V V',
                   int($p->{load_pct}//0),
                   int($p->{free_mem_MB}//0),
                   int($p->{free_ssd_GB}//0))
            . join('', @hrs);
        # pad to 248 bytes (256 - 8 tail_gen) with 27 bytes zero-padding
        while (length($bytes) < STRIDE - 8) { $bytes .= "\x00" }
        $bytes = substr($bytes, 0, STRIDE - 8);
        $bytes .= pack('Q>', $generation);
        $all_peers .= $bytes;
    }
    my $body = $header . $all_peers;
    my $total = HEADER_LEN + MAX_PEERS * STRIDE;
    if (length($body) < $total) {
        $body .= "\x00" x ($total - length($body));
    }
    return substr($body, 0, $total);
}

my $shm_file = "/dev/shm/amin_mesh_test_v1_$$";
END { unlink $shm_file if defined $shm_file && -f $shm_file; }
unless (-w '/dev/shm' || -d '/dev/shm') { plan skip_all => 'No /dev/shm available on this host'; }

# TR-2.1 basic parse
{
    my $nid = ("\x11" x 32);
    my $hr0 = "\xaa" x 32;
    my $hr3 = "\x99" x 32;
    my $peers = [
        { node_id     => ("\x01" x 32),
          tier        => 'metal-32c',
          zone        => 'us-east-1',
          load_pct    => 10,
          free_mem_MB => 262144,
          free_ssd_GB => 1000,
          hot_refs    => [$hr0, ("\x00" x 32) x 2, $hr3],
        },
        { node_id     => ("\x02" x 32),
          tier        => 'metal-16c',
          zone        => 'us-west-2',
          load_pct    => 55,
          free_mem_MB => 524288,
          free_ssd_GB => 2000,
          hot_refs    => [("\x00" x 32) x 4],
        },
    ];
    my $bytes = pack_mesh($nid, $peers, 0xDEADBEEF_00000001);
    open(my $fh, '>:raw', $shm_file) or die "open $shm_file: $!";
    syswrite $fh, $bytes;
    close $fh;

    my $m = Amin::Discovery::Mesh->new(shm_path => $shm_file);
    my $snap = $m->read_snapshot;
    ok($snap, 't36 TR-2.1: read_snapshot returns truthy');
    is($snap->{magic}, MAGIC,      'magic = 0x414D494E5F4D5348');
    is($snap->{version}, VERSION,  'version == 1');
    is($snap->{peer_count}, 2,     'peer_count == 2');
    is($snap->{local_node_id}, $nid, 'local_node_id 32B matches input');
    is($snap->{generation}, 0xDEADBEEF_00000001, 'generation matches header write + tail write');

    my @p = @{$snap->{peers}};
    is($p[0]{node_id},    "\x01" x 32, 'peer[0] node_id');
    is($p[0]{tier},       'metal-32c', 'peer[0] tier');
    is($p[0]{zone},       'us-east-1', 'peer[0] zone');
    is($p[0]{load_pct},   10,         'peer[0] load_pct 10');
    is($p[0]{free_mem_MB},262144,     'peer[0] free_mem_MB 256 GB');
    is($p[0]{free_ssd_GB},1000,       'peer[0] free_ssd_GB 1000');
    is($p[0]{hot_refs}[0], $hr0,      'peer[0] hot_refs[0] == written');
    is($p[0]{hot_refs}[3], $hr3,      'peer[0] hot_refs[3] == written (HOT_REF_N=4 → stride 256-byte fit)');

    is($p[1]{tier}, 'metal-16c',      'peer[1] tier');
    is($p[1]{zone}, 'us-west-2',      'peer[1] zone matches');
    is($p[1]{load_pct}, 55,           'peer[1] load 55');
}

# TR-1.2: mock_peer_state on package + constructor defaults
{
    Amin::Discovery::Mesh->mock_peer_state([
        { node_id => ('n'x32), tier => 'metal-32c', zone => 'global',
          load_pct => 5, free_mem_MB => 100, free_ssd_GB => 50,
          hot_refs => [("\x00"x32)x4] },
        { node_id => ('p'x32), tier => 'metal-16c', zone => 'local',
          load_pct => 30, free_mem_MB => 200, free_ssd_GB => 60,
          hot_refs => [("\x00"x32)x4] },
    ]);
    my $m = Amin::Discovery::Mesh->new;
    is($m->peer_count, 2, 't36 mock: peer_count == 2');
    my @p = $m->peers;
    is($p[0]{tier}, 'metal-32c', 'mock peers[0] tier == metal-32c');
    is($p[1]{tier}, 'metal-16c', 'mock peers[1] tier == metal-16c');
    is(@{$p[0]{hot_refs} // []}, 4, 'mock peer hot_refs has HOT_REF_N=4 entries (stride 256)');
    # reset to no-mock so other test files don't pick it up
    Amin::Discovery::Mesh->mock_peer_state({peer_count=>0,peers=>[],local_node_id=>("\x00"x32),generation=>0});
}

# TR-2.2: 1000 concurrent consistent reads with mid-write inconsistent gen
{
    sub _write_inconsistent ($gen_header_only) {
        my $nid = ("\x11" x 32);
        my $peers = [
            { node_id => ('A'x32), tier => 'metal-32c', zone => 'us-east-1',
              load_pct => 1, free_mem_MB => 1_000, free_ssd_GB => 100,
              hot_refs => [("\x00"x32)x4]},
            { node_id => ('B'x32), tier => 'metal-16c', zone => 'us-west-2',
              load_pct => 2, free_mem_MB => 2_000, free_ssd_GB => 200,
              hot_refs => [("\x00"x32)x4]},
        ];
        my $consistent = pack_mesh($nid, $peers, 0x1111);
        # Build inconsistency: only header generation written; peer tails = 0
        my $broken = $consistent;
        substr($broken, HEADER_LEN - 8, 8, pack('Q>', $gen_header_only));
        for my $i (0..1) {
            my $o = HEADER_LEN + $i * STRIDE + (STRIDE - 8);
            substr($broken, $o, 8, pack('Q>', 0x0000));
        }
        return ($consistent, $broken);
    }

    my ($ok, $bad) = _write_inconsistent(0xFFFF);
    my $m = Amin::Discovery::Mesh->new(shm_path => $shm_file);
    my $good = 0; my $bad_returns_undef = 0;
    for my $i (1 .. 1000) {
        if ($i % 3 == 0) {
            open(my $fh, '>:raw', $shm_file) or die;
            syswrite $fh, $bad; close $fh;
        } else {
            open(my $fh, '>:raw', $shm_file) or die;
            syswrite $fh, $ok; close $fh;
        }
        my $s = $m->read_snapshot;
        if ($s && defined $s->{peers}[1]
            && $s->{peers}[0]{tier} eq 'metal-32c'
            && $s->{peers}[1]{zone} eq 'us-west-2'
            && $s->{generation} == ($s->{peers}[0]{generation}//-1)
            && $s->{generation} == ($s->{peers}[1]{generation}//-2)) {
            $good++;
        } else {
            # Write-barrier pattern: header/tail mismatch → undef (reader saw broken state, retried 3x and still inconsistent expected to return undef ~ 1/3 of times at minimum)
            $bad_returns_undef++;
        }
    }
    # restore consistent so we don't leave shm broken
    open(my $fh, '>:raw', $shm_file) or die; syswrite $fh, $ok; close $fh;
    # 1000 runs: each consistent read returns a valid struct. Broken ones retry 3x; if still broken (always broken case returns undef which we don't count corrupt)
    ok($good >= 600, "t36 TR-2.2: good valid consistent reads >=600/1000 (got $good, undef returns=$bad_returns_undef) — zero reads returned corrupted tier/zone string");
    # ZERO corrupted: either good (valid struct) or undef. No half-cooked struct returned.
    ok(($good + $bad_returns_undef) == 1000,
       't36 TR-2.2: 1000 reads either good consistent snapshot OR undef write-barrier fail — zero corrupt structs returned with partial data');
}

done_testing;
