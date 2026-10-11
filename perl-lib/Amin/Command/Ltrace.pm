package Amin::Command::Ltrace;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{ltrace} }

sub build_argv ($self) {
    my @p = map { ref eq "HASH" ? (values %$_) : $_ } $self->params->@*;
    ($self->name, _flags([qw(p f o output)], $self->flags), @p);
}

1;
