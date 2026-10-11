package Amin::Command::Rustc;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{rustc} }

sub build_argv ($self) {
    my @in = _vals($self->params, "in");
    ($self->name, _flags([qw(o O C g output opt-level codegen)], $self->flags), @in);
}

1;
