package Amin::Command::Hostname;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{hostname} }

sub build_argv ($self) {
    my @t = _vals($self->params, 'name');
    ($self->name, _flags([qw()], $self->flags), @t);
}

1;
