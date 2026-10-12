package Amin::Discovery::Mesh;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Class::Tiny qw(shm_path), {
    _mock         => undef,
    _snapshot     => undef,
};

use constant {
    MAGIC       => unpack('Q>', "\x41\x4D\x49\x4E\x5F\x4D\x53\x48"),
    VERSION     => 1,
    HEADER_LEN  => 64,
    STRIDE      => 256,
    MAX_PEERS   => 64,
    RETRIES     => 3,
    DEFAULT_PATH => '/dev/shm/amin/mesh_state_v1',
    TIER_PAD    => 24,
    ZONE_PAD    => 24,
    HOT_REF_N   => 4,
    HEADER_RESERVED => 12,
};

sub BUILD ($self, $args = {}) {
    $self->{shm_path} //= DEFAULT_PATH;
    return;
}

sub mock_peer_state ($pkg_or_self, $state = undef) {
    state $MOCK = {
        peer_count     => 0,
        local_node_id  => "\x00" x 32,
        peers          => [],
        generation    => 0,
    };
    if (defined $state) {
        if (ref $state eq 'ARRAY') {
            $MOCK = { peer_count => scalar(@$state),
                       local_node_id => "\x00" x 32,
                       peers => $state,
                       generation => 1 };
        } elsif (ref $state eq 'HASH') {
            $MOCK = {
                peer_count    => $state->{peer_count} // 0,
                local_node_id => $state->{local_node_id} // ("\x00" x 32),
                peers         => $state->{peers} // [],
                generation    => $state->{generation} // 1,
            };
        }
    }
    return $MOCK;
}

sub _has_mock ($self) {
    return defined $self->{_mock}
        || (defined __PACKAGE__->mock_peer_state
            && __PACKAGE__->mock_peer_state->{peer_count} > 0);
}

sub local_node_id ($self) {
    my $snap = $self->read_snapshot or return ("\x00" x 32);
    return $snap->{local_node_id};
}

sub peer_count ($self) {
    my $snap = $self->read_snapshot or return 0;
    return $snap->{peer_count};
}

sub peers ($self) {
    my $snap = $self->read_snapshot or return ();
    return @{$snap->{peers}};
}

sub read_snapshot ($self) {
    if ($self->_has_mock) {
        my $m = __PACKAGE__->mock_peer_state;
        return {
            magic         => MAGIC,
            version       => VERSION,
            peer_count    => $m->{peer_count},
            local_node_id => $m->{local_node_id},
            peers         => $m->{peers},
            generation    => $m->{generation},
        };
    }
    my $path = $self->shm_path;
    return undef unless defined $path && length $path;
    return undef unless -f $path;
    for my $attempt (1 .. RETRIES) {
        my $snap = eval { $self->_read_attempt($path) };
        return $snap if $snap;
    }
    return undef;
}

sub _read_attempt ($self, $path) {
    open(my $fh, '<:raw', $path) or return undef;
    my $total = HEADER_LEN + MAX_PEERS * STRIDE;
    sysread($fh, my $buf, $total) or return undef;
    close $fh;
    length($buf) >= HEADER_LEN or return undef;
    my ($magic, $ver, $pcount, $nid, $reserved, $hgen)
        = unpack('Q> v v a32 a12 Q>', substr($buf, 0, HEADER_LEN));
    $magic == MAGIC or return undef;
    $ver == VERSION or return undef;
    $pcount <= MAX_PEERS or return undef;
    my @peers;
    my $off = HEADER_LEN;
    for (1 .. $pcount) {
        length($buf) >= $off + STRIDE or return undef;
        my $peer_bytes = substr($buf, $off, STRIDE);
        my ($pnid, $tlen, $tbytes, $zlen, $zbytes, $load, $fmem, $fssd,
            $hr0,$hr1,$hr2,$hr3, $fvram, $accel, $aitier, $pad, $tgen)
          = unpack('a32 v a24 v a24 C V V a32 a32 a32 a32 V C C a21 Q>',
                   $peer_bytes);
        my $tier = substr($tbytes, 0, ($tlen//0));
        utf8::decode($tier) if defined $tier;
        my $zone = substr($zbytes, 0, ($zlen//0));
        utf8::decode($zone) if defined $zone;
        (defined $tgen && defined $hgen && $tgen == $hgen) or return undef;
        push @peers, {
            node_id      => $pnid,
            tier         => $tier,
            zone         => $zone,
            load_pct     => $load,
            free_mem_MB  => $fmem,
            free_ssd_GB  => $fssd,
            hot_refs     => [$hr0,$hr1,$hr2,$hr3],
            free_vram_MB => $fvram // 0,
            accelerator  => $accel // 0,
            ai_tier      => $aitier // 0,
            generation   => $tgen,
        };
        $off += STRIDE;
    }
    return {
        magic         => $magic,
        version       => $ver,
        peer_count    => $pcount,
        local_node_id => $nid,
        peers         => \@peers,
        generation    => $hgen,
    };
}

1;
