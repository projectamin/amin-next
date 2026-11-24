package Amin::Boot;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use Config;

# Process bootstrap shared by the bin/ entry points (amin, axa).  Run from a
# BEGIN block before anything else loads: it re-execs under the mise-managed
# perl when there is one (the system perl lacks the CPAN set), then puts the
# tree's own libraries on @INC.  `$file` is the script being started, so the
# re-exec runs the same script with the same arguments.

sub init ($class, $file, $root) {
    unless ($ENV{_AMIN_EXECED}) {
        my $mise_shim = ($ENV{HOME} // '') . '/.local/share/mise/shims/perl';
        if (-x $mise_shim && $^X =~ m{^/(usr|bin|sbin|opt)}) {
            $ENV{_AMIN_EXECED} = 1;
            exec $mise_shim, $file, @ARGV
                or die "exec mise perl ($mise_shim) failed: $!";
        }
        for my $d (glob(($ENV{HOME} // '') . '/.local/share/mise/installs/perl/*/*/bin/perl'),
                   glob(($ENV{HOME} // '') . '/.local/share/mise/installs/perl/*/bin/perl')) {
            if (-x $d) {
                $ENV{_AMIN_EXECED} = 1;
                exec $d, $file, @ARGV
                    or die "exec mise perl ($d) failed: $!";
            }
        }
    }

    # cpanm --local-lib-contained installs to three sub-paths under ./local:
    #   lib/perl5                    (pure-perl dists, shared arch)
    #   lib/perl5/$Config{archname}  (XS modules, compiled for this perl's arch)
    #   lib/perl5/$perlver/$archname (old-style local::lib layout, just in case)
    my $arch = $Config{archname};
    my ($perlver) = $^V =~ /^v(\d+\.\d+\.\d+)/;
    unshift @INC,
        "$root/perl-lib",
        "$root/local/lib/perl5",
        "$root/local/lib/perl5/$arch",
        (defined $perlver ? ("$root/local/lib/perl5/$perlver",
                             "$root/local/lib/perl5/$perlver/$arch") : ());
    return;
}

1;
