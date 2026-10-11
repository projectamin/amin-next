package Amin::Command::Fgrep;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{fgrep} }

sub build_argv ($self) {
    my @p = _vals($self->params, "pattern");
    my @f = _vals($self->params, "target");
    return () unless @p || @f;
    ($self->name, _flags([qw(E F i v c n l r extended-regexp fixed-strings ignore-case invert-match count line-number files-with-matches recursive)], $self->flags), @p, @f);
}

1;
