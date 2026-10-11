package Amin::Command::Remove;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';
use Amin::Util::Fold qw(_vals _flags);

sub name    { 'remove'  }
sub element { 'command' }

sub on_command_close ($self) { $self->execute; return; }

sub build_argv ($self) {
    my @t = _vals($self->params, 'target') or return;
    ('rm', _flags([qw(r f R v force recursive)], $self->flags), @t);
}

1;
