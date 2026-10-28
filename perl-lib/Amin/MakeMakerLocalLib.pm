package Amin::MakeMakerLocalLib;

# ═══════════════════════════════════════════════════════════════════════════
# Auto-loaded via PERL5OPT in .mise.toml [env].
#
# Prepend the project-local include and lib directories so XS modules can
# find libblake3 and liboqs. Do not put LIBS or CCFLAGS in PERL_MM_OPT:
# ExtUtils::MakeMaker::parse_args copies those over the Makefile.PL values,
# which drops -lxml2 (and any other module-specific -l flags). The .so then
# loads with "undefined symbol: xmlMemMalloc".
# ═══════════════════════════════════════════════════════════════════════════

use strict;
use warnings;
use Cwd qw(abs_path);

my $local = $ENV{AMIN_HOME} ? abs_path("$ENV{AMIN_HOME}/local") : undef;

if ($local && -d "$local/include" && -d "$local/lib" && !$Amin::MakeMakerLocalLib::WRAPPED) {
    $Amin::MakeMakerLocalLib::WRAPPED = 1;

    my $inc_flag = "-I$local/include";
    my $lib_flag = "-L$local/lib";

    require ExtUtils::MakeMaker;
    my $orig = \&ExtUtils::MakeMaker::WriteMakefile;
    no warnings 'redefine';
    *ExtUtils::MakeMaker::WriteMakefile = sub {
        my %args = @_;
        $args{INC}     = _prepend_flag($inc_flag, $args{INC});
        $args{CCFLAGS} = _prepend_flag($inc_flag, $args{CCFLAGS});
        $args{LIBS}    = _prepend_libs($lib_flag, $args{LIBS});

        # A LIBS/CCFLAGS entry already in the environment would still win
        # inside WriteMakefile, after the merge above.
        my $saved = $ENV{PERL_MM_OPT};
        _drop_overriding_mm_opt();
        my $mm = eval { $orig->(%args) };
        my $err = $@;
        if (defined $saved) {
            $ENV{PERL_MM_OPT} = $saved;
        }
        die $err if $err;
        return $mm;
    };
}

sub _prepend_flag {
    my ($flag, $existing) = @_;
    return $flag unless defined $existing && $existing =~ /\S/;
    return $existing if index($existing, $flag) >= 0;
    return "$flag $existing";
}

sub _prepend_libs {
    my ($flag, $libs) = @_;
    return [$flag] unless defined $libs;
    if (ref $libs eq 'ARRAY') {
        return [$flag] unless @$libs;
        return [map { _prepend_flag($flag, $_) } @$libs];
    }
    return _prepend_flag($flag, $libs);
}

sub _drop_overriding_mm_opt {
    my $opt = $ENV{PERL_MM_OPT} // return;
    $opt =~ s/(?:^|\s)(?:CCFLAGS|LIBS)=(?:"[^"]*"|'[^']*'|\S+)//g;
    $opt =~ s/^\s+|\s+$//g;
    if (length $opt) {
        $ENV{PERL_MM_OPT} = $opt;
    } else {
        delete $ENV{PERL_MM_OPT};
    }
}

1;
