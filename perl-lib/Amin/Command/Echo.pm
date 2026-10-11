package Amin::Command::Echo;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Command::Pass';
use Amin::Util::Fold qw(_flags);

sub name { 'echo' }

sub build_argv ($self) {
    ('echo', _flags([qw(n e)], $self->flags),
            map { ref eq 'HASH' ? ($_->{text} // ()) : $_ } $self->params->@*);
}

1;
