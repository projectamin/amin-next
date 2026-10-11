package Amin::Command::Pass;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

sub element { 'command' }

sub on_command_close ($self) { $self->execute; return; }

1;
