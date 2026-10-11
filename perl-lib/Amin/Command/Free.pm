package Amin::Command::Free;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{free} }

sub build_argv ($self) {
    ($self->name, _flags([qw(h m g human)], $self->flags));
}

1;
