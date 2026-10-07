package Amin::Log::Standard;
use v5.38; use warnings; use utf8;

use Class::Tiny qw(stderr color errors warns);
sub BUILD ($self, @) {
    $self->{stderr} //= 1;
    $self->{color}  //= -t STDERR ? 1 : 0;
    $self->{errors} //= 0;
    $self->{warns}  //= 0;
}

my %C = (info => "\e[36m", success => "\e[32m",
         warn => "\e[33m", error   => "\e[31m", R => "\e[0m");

for my $lvl (qw(info success warn error)) {
    no strict 'refs';
    *$lvl = sub ($self, $msg = '') {
        $self->{errors}++ if $lvl eq 'error';
        $self->{warns}++  if $lvl eq 'warn';
        return unless $self->{stderr};
        my $c = $self->{color} ? $C{$lvl} : '';
        say STDERR "${c}[@{[uc $lvl]}]@{[$self->{color} ? $C{R} : '']} $msg";
        return $self;
    };
}

sub error_count ($self) { $self->{errors} // 0 }
sub warn_count  ($self) { $self->{warns}  // 0 }

1;
