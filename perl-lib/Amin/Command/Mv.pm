package Amin::Command::Mv;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{mv} }

sub build_argv ($self) {
    my @src = _vals($self->params, "src");
    my @dst = _vals($self->params, "dst");
    return () unless @src || @dst;
    ($self->name, _flags([qw(f i n u v b interactive no-clobber)], $self->flags), @src, @dst);
}

1;
