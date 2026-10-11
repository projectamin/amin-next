package Amin::Command::Tar;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{tar} }

sub build_argv ($self) {
    my @t = _vals($self->params, "target");
    return () unless @t;
    ($self->name, _flags([qw(x c v f z j J t p extract create verbose file gzip bzip2 xz preserve-permissions)], $self->flags), @t);
}

1;
