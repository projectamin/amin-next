package Amin::Command::Gfortran;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{gfortran} }

sub build_argv ($self) {
    my @in = _vals($self->params, "in");
    ($self->name, _flags([qw(o O c g I L std output optimize)], $self->flags), @in);
}

1;
