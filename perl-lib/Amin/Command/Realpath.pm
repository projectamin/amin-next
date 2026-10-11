package Amin::Command::Realpath;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{realpath} }

sub build_argv ($self) {
    my @t = _vals($self->params, "target");
    return () unless @t;
    ($self->name, _flags([qw(m q e canonicalize-missing quiet strip)], $self->flags), @t);
}

1;
