package Amin::Test::Dispatch::TraceEnd;

# Amin::Test::Dispatch::TraceEnd — t/19 subtest 2 helper.
# Records (LocalName, _trace_marker_attr) pairs on start_element into a
# filter-local array that the test post-hoc searches with grep for specific
# ordering constraints (profile THEN late-injected synth).
#
# Replacement for the historical:
#   our @TraceEnd::Seen = (); push @Seen, [$ln, $marker]
# with its manual TraceEnd::reset() between subtests.
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';

use Class::Tiny { trace_pairs => sub { [] } };

sub BUILD ($self, @) {
    $self->label('TraceEnd(end-position element/marker trace)');
}

sub trace_pairs_count ($self, %matcher) {
    my ($ln_want, $marker_want) = delete @matcher{qw(ln marker)};
    my $n = 0;
    for my $pair ($self->trace_pairs->@*) {
        my ($ln, $marker) = @$pair;
        next if defined $ln_want     && $ln ne $ln_want;
        next if defined $marker_want && $marker ne $marker_want;
        $n++;
    }
    return $n;
}

sub trace_first_index ($self, %m) {
    my ($ln_want, $marker_want) = delete @m{qw(ln marker)};
    for my $i (0..$#{$self->trace_pairs}) {
        my ($ln, $marker) = $self->trace_pairs->[$i]->@*;
        next if defined $ln_want     && $ln ne $ln_want;
        next if defined $marker_want && $marker ne $marker_want;
        return $i;
    }
    return undef;
}

sub start_element ($self, $el) {
    my $ln     = $el->{LocalName} // '';
    my $marker = '';
    for my $a (values %{$el->{Attributes} // {}}) {
        $marker = $a->{Value} if ($a->{LocalName} // '') eq '_trace_marker';
    }
    push $self->trace_pairs->@*, [$ln, $marker];
    return $self->SUPER::start_element($el);
}

1;
