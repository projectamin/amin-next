package Amin::Command::Sed;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{sed} }

sub build_argv ($self) {
    my @s = _vals($self->params, "script");
    my @f = _vals($self->params, "target");
    return () unless @s || @f;
    ($self->name, _flags([qw(n e f i r s quiet expression file in-place separate)], $self->flags), @s, @f);
}

1;
