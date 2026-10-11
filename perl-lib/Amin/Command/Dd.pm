package Amin::Command::Dd;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{dd} }

sub build_argv ($self) {
    my @p;
    for my $h ($self->params->@*) {
        if (ref $h eq "HASH") { push @p, map { "$_=" . $h->{$_} } keys %$h }
        else                   { push @p, $h }
    }
    ($self->name, _flags([qw(if of bs count skip seek conv status ibs obs)], $self->flags), @p);
}

1;
