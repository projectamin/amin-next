package Amin::Command::Curl;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{curl} }

sub build_argv ($self) {
    my @u = _vals($self->params, "url");
    return () unless @u;
    ($self->name, _flags([qw(s L o O u k silent location output remote-name user insecure)], $self->flags), @u);
}

1;
