package Amin::Log::Standard;
use v5.38; use warnings; use utf8;

use Class::Tiny qw(stderr color errors warns);
sub BUILD ($self, @) {
    $self->{stderr} //= 1;
    $self->{color}  //= -t STDERR ? 1 : 0;
    $self->{errors} //= 0;
    $self->{warns}  //= 0;
    $self->{halted} //= 0;
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

# Fail-fast latch.  A command whose subprocess exit is not clean calls halt()
# so the Dispatcher can stop dispatching the rest of the document — the 3.0
# shape of amin-legacy, where a failing command set $spec->{amin_error} and the
# Dispatcher swapped every later element to Handler::Empty.  The latch lives on
# the Log because that is the one object every filter in the chain shares.
sub halt ($self, $reason = '') {
    $self->{halted} = 1;
    $self->{halt_reason} = $reason if defined $reason && length $reason;
    return $self;
}
sub halted      ($self) { $self->{halted} // 0 }
sub halt_reason ($self) { $self->{halt_reason} }

1;
