package Amin::Command::Wget;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{wget} }

sub build_argv ($self) {
    my @u = _vals($self->params, "url");
    return () unless @u;
    ($self->name, _flags([qw(q c O P t T quiet continue output-document directory-prefix tries timeout no-check-certificate user-agent)], $self->flags), @u);
}

1;
