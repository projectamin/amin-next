package Amin::Command::Cc;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{cc} }

sub build_argv ($self) {
    my @in = _vals($self->params, "in");
    ($self->name, _flags([qw(o O c g W I L D E S shared static pie std include define output optimize warning)], $self->flags), @in);
}

1;
