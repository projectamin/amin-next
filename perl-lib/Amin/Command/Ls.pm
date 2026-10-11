package Amin::Command::Ls;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{ls} }

sub build_argv ($self) {
    my @t = _vals($self->params, "target");
    return () unless @t;
    ($self->name, _flags([qw(a l h i n s r t R A d color time-style)], $self->flags), @t);
}

1;
