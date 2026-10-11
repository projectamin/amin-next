package Amin::Command::Mkdir;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Command::Pass';
use Amin::Util::Fold qw(_vals _flags);

sub name { 'mkdir' }

sub build_argv ($self) {
    my @t = _vals($self->params, 'target') or return;
    ('mkdir', _flags([qw(p m mode parents)], $self->flags), @t);
}

1;
