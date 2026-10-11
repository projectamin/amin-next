package Amin::Command::Make;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{make} }

sub build_argv ($self) {
    my @p = map { ref eq "HASH" ? (values %$_) : $_ } $self->params->@*;
    ($self->name, _flags([qw(j C f k n jobs directory file keep-going dry-run)], $self->flags), @p);
}

1;
