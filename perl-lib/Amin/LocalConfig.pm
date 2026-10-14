package Amin::LocalConfig;

# ═══════════════════════════════════════════════════════════════════════════
# Drop-in Config override — loaded by Perl at startup via PERL5OPT or by
# being installed as sitelibexec/Config.pm.  Adds the project's ./local/lib
# and ./local/include to $Config{ccflags} and $Config{libs} so that
# ExtUtils::MakeMaker and XS module builds find locally-built C libraries
# without system packages or Alien:: dists.
#
# Usage: add to .mise.toml [env]:
#     PERL5OPT = "-MAmin::LocalConfig"
# ═══════════════════════════════════════════════════════════════════════════

use strict;
use warnings;
use Cwd qw(abs_path);

my $local = $ENV{AMIN_HOME} ? abs_path("$ENV{AMIN_HOME}/local") : undef;

if ($local && -d "$local/include" && -d "$local/lib") {
    # Config values are read-only, so we modify them in the importer's
    # namespace.  This is the standard trick for site-level Config overrides.
    my $caller_pkg = caller(0) ? caller(0) : 'main';
    no strict 'refs';
    my $cv = ${$caller_pkg . '::Config'}{'ccflags'};
    ${$caller_pkg . '::Config'}{'ccflags'} = "-I$local/include $cv";
    my $lv = ${$caller_pkg . '::Config'}{'libs'};
    ${$caller_pkg . '::Config'}{'libs'} = "-L$local/lib $lv";
}

1;
