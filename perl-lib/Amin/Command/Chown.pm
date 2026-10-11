package Amin::Command::Chown;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{chown} }

sub build_argv ($self) {
    my @mode = _vals($self->params, "mode");
    my @t    = _vals($self->params, "target");
    return () unless @mode || @t;
    ($self->name, _flags([qw(R v c f h no-dereference changes dereference)], $self->flags), @mode, @t);
}

1;
