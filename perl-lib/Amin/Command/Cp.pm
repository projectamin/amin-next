package Amin::Command::Cp;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{cp} }

sub build_argv ($self) {
    my @src = _vals($self->params, "src");
    my @dst = _vals($self->params, "dst");
    return () unless @src || @dst;
    ($self->name, _flags([qw(r f R p v i a L H P no-preserve preserve interactive archive no-dereference)], $self->flags), @src, @dst);
}

1;
