package Amin::Artifact;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::Artifact — one CAS/file path for every filter that produces bytes.
#
# AI filters (Embed, Music) and Content filters all need the same two things:
#   bc_put($bytesref)  → (blake3-hex, size) via bctool when present, in-process
#                        BLAKE3 otherwise (the pipeline stays auditable);
#   write_bytes($path, $bytes) → materialise an artifact under a caller-vetted
#                        path (Mode=run only; path validation lives in the
#                        caller, because the caller owns the policy).
# ═══════════════════════════════════════════════════════════════════════════

use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

use Exporter 'import';
our @EXPORT_OK = qw(bc_put bc_blake3 write_bytes);

sub bc_put ($dataref) {
    require Amin::ToolPaths;
    my $bctool = Amin::ToolPaths::tool_bctool();
    return bc_blake3($dataref)
        unless defined $bctool && length $bctool && _cmd_exists($bctool);

    my $slab = _slab();
    my ($out, $err) = ('', '');
    my $in = $$dataref;
    require IPC::Run;
    my $h = IPC::Run::harness([$bctool, 'put', '--slab', $slab],
        \$in, \$out, \$err, debug => 0);
    eval { IPC::Run::start($h); IPC::Run::finish($h) };
    my $rc = $? >> 8;
    return bc_blake3($dataref) if $@ || $rc != 0;

    my %kv;
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $kv{$k} = $v if defined $v;
    }
    return unless exists $kv{hash} && length($kv{hash}) == 64;
    return ($kv{hash}, $kv{size} // length($$dataref));
}

sub bc_blake3 ($dataref) {
    require Digest::BLAKE3;
    my $hasher = Digest::BLAKE3::->new();
    $hasher->add($$dataref);
    return ($hasher->hexdigest(), length($$dataref));
}

sub write_bytes ($path, $bytes) {
    return undef unless defined $path && length $path;
    return undef unless defined $bytes;
    require File::Basename;
    require File::Path;
    my $dir = File::Basename::dirname($path);
    File::Path::make_path($dir) if length $dir && !-d $dir;
    open(my $fh, '>:raw', $path) or return undef;
    print {$fh} $bytes or do { close $fh; return undef };
    close $fh or return undef;
    return $path;
}

sub _slab {
    state $default = do {
        require File::Temp;
        File::Temp::tempdir(CLEANUP => 1) . '/default.slab';
    };
    return $default;
}

sub _cmd_exists ($cmd) {
    return 0 unless defined $cmd && length $cmd;
    return 1 if -x $cmd;
    return 1 if $cmd =~ m{/};
    for my $d (split /:/, $ENV{PATH} // '/usr/bin:/bin') {
        return 1 if -x "$d/$cmd";
    }
    return 0;
}

1;
