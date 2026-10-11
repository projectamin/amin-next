package Amin::Command::Gawk;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{gawk} }

sub build_argv ($self) {
    my @s = _vals($self->params, "script");
    my @f = _vals($self->params, "target");
    return () unless @s || @f;
    ($self->name, _flags([qw(f F v W file field-separator assign)], $self->flags), @s, @f);
}

1;
