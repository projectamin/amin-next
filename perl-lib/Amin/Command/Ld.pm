package Amin::Command::Ld;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{ld} }

sub build_argv ($self) {
    my @in = _vals($self->params, "in");
    ($self->name, _flags([qw(o e L l output entry library-path library)], $self->flags), @in);
}

1;
