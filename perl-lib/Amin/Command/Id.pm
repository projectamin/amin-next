package Amin::Command::Id;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{id} }

sub build_argv ($self) {
    ($self->name, _flags([qw(u g n real user group name)], $self->flags));
}

1;
