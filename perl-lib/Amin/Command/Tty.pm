package Amin::Command::Tty;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{tty} }

sub build_argv ($self) {
    ($self->name, _flags([qw(s silent)], $self->flags));
}

1;
