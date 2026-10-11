package Amin::Command::Mount;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{mount} }

sub build_argv ($self) {
    my @d = _vals($self->params, "device");
    my @t = _vals($self->params, "target");
    return () unless @d || @t;
    ($self->name, _flags([qw(t o options bind read-only remount)], $self->flags), @d, @t);
}

1;
