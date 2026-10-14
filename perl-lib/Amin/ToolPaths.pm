package Amin::ToolPaths;

# ═══════════════════════════════════════════════════════════════════════════
# Canonical resolver for the rust-built tool binaries.
#
# Cargo builds land in ./target/{debug,release} via CARGO_TARGET_DIR (= $PWD/
# target in .mise.toml); the legacy layout ./rust/target/{debug,release} is
# kept as a fallback for checkouts that build without the override, then
# PATH.  $ENV{AMIN_BCTOOL} / $ENV{AMIN_AMINEXEC} pin an authority-managed
# install (metal mode grants landlock FILE__EXECUTE per-path, so the
# resolved absolute path must be stable).
#
# One resolver, not six: bitcache storage, AI embeds, the sandbox executor
# and the test signer originally resolved these independently and drifted.
# ═══════════════════════════════════════════════════════════════════════════

use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

use Exporter 'import';
our @ISA       = ('Exporter');
our @EXPORT_OK = qw(tool_aminexec tool_bctool);

sub _project_root {
    # __FILE__ may be ABSOLUTE (()=-@INC normalization) or a bare relative
    # @INC entry like 'perl-lib/Amin/ToolPaths.pm' — only trust the strip
    # when the result is a real directory, else assume we run at project root.
    if ((my $r = __FILE__) =~ s{/perl-lib/Amin/ToolPaths\.pm$}{}) {
        return $r if -d $r;
    }
    require Cwd;
    return Cwd::getcwd();
}

sub _pick ($env_key, $bin) {
    return $ENV{$env_key} if defined $ENV{$env_key} && length $ENV{$env_key};
    my $root = _project_root();
    my @cands = (
        "$root/target/debug/$bin",   "$root/target/release/$bin",
        "$root/rust/target/debug/$bin", "$root/rust/target/release/$bin",
    );
    for my $c (@cands) { return $c if -x $c }
    for my $d (split /:/, $ENV{PATH} // '/usr/bin:/bin') {
        return "$d/$bin" if -x "$d/$bin";
    }
    return '';
}

sub tool_aminexec {
    state $t;
    return $t if defined $t;
    return $t = _pick('AMIN_AMINEXEC', 'aminexec');
}

sub tool_bctool {
    state $t;
    return $t if defined $t;
    return $t = _pick('AMIN_BCTOOL', 'bctool');
}

1;
