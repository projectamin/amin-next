package Amin::Command::Objdump;
use v5.38; use warnings; use utf8; use experimental qw(signatures);
use parent q{Amin::Command::Pass};
use Amin::Util::Fold qw(_vals _flags);

sub name { q{objdump} }

sub build_argv ($self) {
    my @t = _vals($self->params, "target");
    return () unless @t;
    ($self->name, _flags([qw(d D f h t S disassemble disassemble-all file-headers section-headers full-contents)], $self->flags), @t);
}

1;
