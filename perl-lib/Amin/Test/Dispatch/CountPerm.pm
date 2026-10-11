package Amin::Test::Dispatch::CountPerm;

# Amin::Test::Dispatch::CountPerm — t/19 subtest 1 helper.
# Counts all start / end / character bytes passing through; emits
# assertions at end_document against $self->expected_starts / _ends / _min_chars_bytes.
# This lives in the 'permanent' filter position, so it MUST see events that
# a later 'begin' filter drops; that's exactly what TR-2.1 verifies.
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';

use Class::Tiny qw(expected_starts expected_ends expected_min_chars_bytes
                   start_count end_count chars_sum_bytes);

sub BUILD ($self, @) {
    $self->{start_count} = 0;
    $self->{end_count}   = 0;
    $self->{chars_sum_bytes} = 0;
    $self->label('CountPerm(permanent-position event counter)');
}

sub start_element ($self, $el) {
    $self->{start_count}++;
    return $self->SUPER::start_element($el);
}

sub end_element   ($self, $el) {
    $self->{end_count}++;
    return $self->SUPER::end_element($el);
}

sub characters    ($self, $d) {
    my $len = length($d->{Data} // '');
    $self->{chars_sum_bytes} += $len if $len;
    return $self->SUPER::characters($d);
}

sub end_document ($self, @) {
    if (defined(my $want = $self->expected_starts)) {
        $self->assert_seen_count(
            "permanent saw $want start_elements (before any begin filter drops)",
            kind => 'start', count => $want);
        if (defined &Test2::V0::is) {
            Test2::V0::is($self->{start_count}, $want,
                "CountPerm start_count == $want");
        }
        $self->_bump($self->{start_count} == $want);
    }
    if (defined(my $want = $self->expected_ends)) {
        if (defined &Test2::V0::is) {
            Test2::V0::is($self->{end_count}, $want,
                "CountPerm end_count == $want");
        }
        $self->_bump($self->{end_count} == $want);
    }
    if (defined(my $want = $self->expected_min_chars_bytes)) {
        if (defined &Test2::V0::cmp_ok) {
            Test2::V0::cmp_ok($self->{chars_sum_bytes}, '>=', $want,
                "CountPerm chars_sum_bytes >= $want (sees dropped chars too)");
        }
        $self->_bump($self->{chars_sum_bytes} >= $want);
    }
    return $self->SUPER::end_document({});
}

1;
