package Amin::Command::Remove;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Command::Pass';
use Amin::Util::Fold qw(_vals _flags);

sub name { 'remove' }

sub build_argv ($self) {
    my @t = _vals($self->params, 'target') or return;
    ('rm', _flags([qw(r f R v force recursive)], $self->flags), @t);
}

1;
