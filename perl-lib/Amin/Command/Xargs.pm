package Amin::Command::Xargs;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{xargs} }

sub build_argv ($self) {
    my @t = _vals($self->params, "target");
    return () unless @t;
    ($self->name, _flags([qw(I n t r P replace max-args verbose no-run-if-empty max-procs)], $self->flags), @t);
}

1;
