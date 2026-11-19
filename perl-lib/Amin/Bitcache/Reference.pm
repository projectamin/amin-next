package Amin::Bitcache::Reference;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# One resolver for a signed, content-addressed Bitcache reference:
#
#   bitcache://blake3/<64-hex-content-hash>?signer=<name>&ts=<unix>&vk=<…>&sig=<…>
#
# Identity is the content hash; the signature (ML-DSA-87) is checked by
# `bctool verify` — never re-implemented here, because PQ verification must
# live in exactly one place (proxy-plan §7).  Callers: Amin::Machine::MachineSpec
# and, later, the proxy config loader and route specs — so a profile, a machine
# spec and a proxy config all resolve byte-identically through one code path
# (proxy-plan §5.13), instead of each carrying its own fetch+verify.
#
# A reference is *addressed* when it names a hash — either parsed from a
# bitcache:// URI (uri=, or path= carrying one) or handed over directly as
# hash=.  An unaddressed reference is just a filesystem path, and the caller
# resolves that itself.  Nothing here is fail-open: a failed get or a failed
# verify yields no bytes, and the caller degrades closed (an empty allow-list
# for a spec, a refusal to start for a config).
#
# Field names deliberately match MachineSpec's historical kwarg surface
# (signer_name / signer_ts / signer_vk / signer_sig / trust_anchor_dir /
# slab_path / bctool_path), so adopting this class does not move the contract.

sub new ($class, %o) {
    $o{hash} = $o{bc_hash} if defined $o{bc_hash} && !defined $o{hash};
    return bless { %o }, $class;
}

# Parse a bitcache:// URI into {hash, signer_name, signer_ts, signer_vk,
# signer_sig}.  A URI whose scheme/authority/hash does not match leaves the
# reference unaddressed (the caller then treats it as a plain path).
sub parse ($self, $uri = undef) {
    $uri //= $self->{uri};
    unless (defined $uri && length $uri) {
        my $p = $self->{path};
        $uri = $p if defined $p && $p =~ m{^bitcache://};
    }
    return $self unless defined $uri && length $uri;

    require URI;
    require URI::Escape;
    my $u = eval { URI->new($uri) };
    return $self unless $u && defined $u->scheme && $u->scheme eq 'bitcache';
    return $self unless ($u->authority // '') eq 'blake3';

    my $path = $u->path // '';
    $path =~ s{^/}{};
    return $self unless length($path) == 64 && $path =~ /^[0-9a-f]{64}$/;
    $self->{hash} = $path;

    my %q = $u->query_form;
    my %map = (signer => 'signer_name', ts => 'signer_ts',
               sig    => 'signer_sig',  vk => 'signer_vk');
    for my $key (keys %map) {
        $self->{$map{$key}} = $q{$key}
            if exists $q{$key} && defined $q{$key} && length $q{$key};
    }
    return $self;
}

sub addressed ($self) {
    return defined $self->{hash} && $self->{hash} =~ /^[0-9a-f]{64}$/;
}

sub hash ($self) { $self->{hash} }

sub _bctool ($self) {
    require Amin::ToolPaths;
    my $default = Amin::ToolPaths::tool_bctool();
    return $self->{bctool_path} if defined $self->{bctool_path};
    return length $default ? $default : 'bctool';
}

sub _slab ($self) {
    state $default = do {
        require File::Temp;
        File::Temp::tempdir(CLEANUP => 1) . '/default.slab';
    };
    my $p = $self->{slab_path};
    return (defined $p && length $p) ? $p : $default;
}

# The object's raw bytes as a scalar ref, or undef when the CAS does not have
# the hash (or bctool fails).  Bytes only — no verification yet.
sub get ($self) {
    return unless $self->addressed;
    require IPC::Run;
    my ($in, $out, $err) = ('', '', '');
    my $h = IPC::Run::harness(
        [$self->_bctool, 'get', '--slab', $self->_slab, '--hash', $self->{hash}],
        \$in, \$out, \$err, debug => 0);
    eval { IPC::Run::start($h); IPC::Run::finish($h) };
    return if $@ || ($? >> 8) != 0;
    return \$out;
}

# 1 when the signature binds the hash to a trusted verification key, 0
# otherwise.  The VK is inline (`vk=`) or read from the trust-anchor directory
# under sha256(signer).vk, exactly as MachineSpec always resolved it.
sub verify ($self) {
    my ($name, $ts, $sig) = @{$self}{qw(signer_name signer_ts signer_sig)};
    return 0 unless defined $name && length $name;
    return 0 unless defined $ts   && length $ts;
    return 0 unless defined $sig  && length $sig;

    my $vk = $self->{signer_vk};
    unless (defined $vk && length $vk) {
        my $ta = $self->{trust_anchor_dir};
        return 0 unless defined $ta && length $ta;
        require Digest::SHA;
        $vk = "$ta/" . Digest::SHA::sha256_hex($name) . '.vk';
        return 0 unless -f $vk;
    }

    require IPC::Run;
    my ($in, $out, $err) = ('', '', '');
    my $h = IPC::Run::harness(
        [$self->_bctool, 'verify',
            '--slab', $self->_slab, '--hash', $self->{hash},
            '--name', $name, '--ts', $ts, '--vk', $vk, '--sig', $sig],
        \$in, \$out, \$err, debug => 0);
    eval { IPC::Run::start($h); IPC::Run::finish($h) };
    return ($@ || ($? >> 8) != 0) ? 0 : 1;
}

# The verified object as a string, or undef — get and verify, fail-closed.
sub resolve ($self) {
    my $raw = $self->get or return undef;
    return undef unless length $$raw;
    return undef unless $self->verify;
    return $$raw;
}

# Is this string a bitcache:// reference at all?  Lets a caller decide between
# "resolve from the CAS" and "read a local path" before constructing anything.
# A plain predicate, deliberately callable before a Reference exists.
sub is_reference ($s) {
    return defined $s && $s =~ m{^bitcache://};
}

1;
