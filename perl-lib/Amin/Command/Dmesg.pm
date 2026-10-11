package Amin::Command::Dmesg;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{dmesg} }

sub build_argv ($self) {
    ($self->name, _flags([qw()], $self->flags));
}

1;
