package Amin::MakeMakerLocalLib;

# ═══════════════════════════════════════════════════════════════════════════
# Auto-loaded via PERL5OPT in .mise.toml [env].
#
# ExtUtils::MakeMaker::WriteMakefile discards its %args and rebuilds from
# PERL_MM_OPT + @ARGV.  So we inject our local lib paths into PERL_MM_OPT
# before any Makefile.PL runs.  This makes XS modules (Digest::BLAKE3, etc.)
# find locally-built C libraries without system packages or Alien:: dists.
# ═══════════════════════════════════════════════════════════════════════════

use strict;
use warnings;
use Cwd qw(abs_path);

my $local = $ENV{AMIN_HOME} ? abs_path("$ENV{AMIN_HOME}/local") : undef;

if ($local && -d "$local/include" && -d "$local/lib") {
    my $cc   = "-I$local/include";
    my $libs = "-L$local/lib -lblake3 -loqs";

    my $prev = $ENV{PERL_MM_OPT} || '';
    # Strip any old Amin local paths so re-loading is idempotent
    my $lib_path = quotemeta("$local/lib");
    $prev =~ s/\s*-I\Q$local\E\/include//g;
    $prev =~ s/\s*-L$lib_path\b[^ ]*//g;
    $prev =~ s/\s*CCFLAGS\s*=\S+//g;
    $prev =~ s/\s*LIBS\s*=\S+(?:\s+\S+)*//g;
    $prev =~ s/^\s+//;
    # PERL_MM_OPT is space-separated KEY=VALUE pairs.
    # LIBS value contains spaces so it MUST be double-quoted for
    # ExtUtils::MakeMaker::_shellwords (Text::ParseWords).
    my $extra = "CCFLAGS=$cc LIBS=\"$libs\"";
    $ENV{PERL_MM_OPT} = $prev ? "$prev $extra" : $extra;
}
1;
