package Amin::Command::Rg;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{rg} }

sub build_argv ($self) {
    my @p = _vals($self->params, "pattern");
    my @f = _vals($self->params, "target");
    return () unless @p || @f;
    ($self->name, _flags([qw(i v c n l ignore-case invert-match count line-number files-with-matches)], $self->flags), @p, @f);
}

1;
