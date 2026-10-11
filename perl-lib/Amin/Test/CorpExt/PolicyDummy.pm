package Amin::Test::CorpExt::PolicyDummy;

# Amin::Test::CorpExt::PolicyDummy — proof-of-concept Amin::Test::Handler
# subclass that replaces the inline `package CorpExt::Policy::Dummy` blob
# that historically lived inside t/05-dispatcher.t.
#
# Demonstrates the Amin::Test pattern:
#   1. IS-A Amin::Test::Handler (so @seen filter-local, not package-global).
#   2. Declares the specific extra capture (SOX custom namespace hit count)
#      it needs on top of default start/end/chars tracking.
#   3. end_document composes assert_seen_count, assert_custom_ns_seen, and
#      pair-count parity checks using base helpers, NOT Test2::V0 calls
#      scattered through the .t body.
#   4. report() returns true/false for easy `ok($t->report, …)` in harness.
#
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';

use Amin qw(NS);
use Class::Tiny qw(ExpectedMinEvents);

our $NS_SOX = 'https://corp.example.test/ns/sox/v1';

sub BUILD ($self, @) {
    $self->label('CorpExt::PolicyDummy (Amin::Test subclass)');
    $self->{_sox_count} = 0;
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    if ($ns eq $NS_SOX) {
        $self->{_sox_count}++;
    }
    return $self->SUPER::start_element($el);
}

sub end_document ($self, @) {
    my $want_events = $self->ExpectedMinEvents // 5;

    $self->assert_seen_count(
        sprintf('CorpExt filter saw ≥ %d SAX events (custom-extensibility DI-2 guard)',
                $want_events),
        kind   => 'start',
        count  => 2);
    my $total = scalar $self->seen->@*;
    my $ok_events = ($total >= $want_events);
    if (defined &Test2::V0::cmp_ok) {
        Test2::V0::cmp_ok($total, '>=', $want_events,
            'custom filter received events (start/end/chars: got ' . $total . ')');
    }
    $self->_bump($ok_events);

    if (defined &Test2::V0::cmp_ok) {
        Test2::V0::cmp_ok(($self->{_sox_count} // 0), '>=', 1,
            'custom filter DID see sox:* (NS_SOX) element — not stripped by chain');
    }
    $self->_bump(($self->{_sox_count} // 0) >= 1);

    # Pair-count parity: result starts == status starts.
    my $rc = 0; my $sc = 0;
    for my $ev ($self->seen->@*) {
        next unless $ev->{kind} eq 'start';
        ++$rc if ($ev->{ln} // '') eq 'result';
        ++$sc if ($ev->{ln} // '') eq 'status';
    }
    if ($rc == 0 && $sc == 0) {
        if (defined &Test2::V0::ok) {
            Test2::V0::ok(1,
                'pair-count trivially holds (0 result / 0 status events in ext-test profile)');
        }
        $self->_bump(1);
    } else {
        if (defined &Test2::V0::is) {
            Test2::V0::is($rc, $sc,
                "pair-count parity result↔status (rc=$rc sc=$sc)");
        }
        $self->_bump($rc == $sc);
    }

    return $self->SUPER::end_document({});
}

1;
