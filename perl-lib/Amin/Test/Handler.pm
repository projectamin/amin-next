package Amin::Test::Handler;

# Amin::Test::Handler — base class for DI-1 test filters.
#
# Every test in t/*.t that needs to intercept / observe / assert on the SAX
# event stream IS-AN Amin::Test::Handler subclass.  The pattern replaces the
# historical inline `package # no-index … our @SeenEvents` blobs scattered
# through t/*.t files with a first-class contract:
#
#   (1) Filter-local event capture (no package-global our @Seen pollution
#       that accidentally cross-talks between runs).
#   (2) Uniform SAX-first assertion helpers: assert_seen_count,
#       assert_seen_some, assert_seen_none, assert_elements_between —
#       each composes with Test2::V0 under prove while keeping assertions
#       structured so a future collector filter could also render them as
#       <amin:test_assert kind=pass|fail> SAX elements (DI-1 compatible
#       in-dashboard test reports without a TAP side-channel).
#   (3) report() hook called at end_document that a test can delegate to
#       so the test body collapses to:
#
#           my $t = Amin::Test::MyThing->new(…expectations…);
#           Amin::Machine::Dispatcher->run(Handler => …, extra_filters => [$t]);
#           $t->report;
#           done_testing;
#
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode TestName AssertionsFailed AssertionsPassed),
    {
        seen          => sub { [] },
        seen_custom_ns=> sub { 0 },
        label         => 'Amin::Test::Handler',
    };

# ── Per-filter event capture ────────────────────────────────────────────
# Subclasses override _track_event($kind, $el_or_d) to add their own
# derived metrics; default implementation pushes a uniform record onto
# $self->seen so assert_seen_* helpers work out of the box.
sub _track_event ($self, $kind, $payload = {}) {
    push $self->seen->@*, { kind => $kind, %$payload };
    return;
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    $self->_track_event(start => { ns => $ns, ln => $ln,
        attrs => [ map {; { LocalName => $_->{LocalName},
                            Value     => $_->{Value} } }
                   grep { ref($_) eq 'HASH' } values %{ $el->{Attributes} // {} } ] });
    if (length($ns) && $ns ne NS()) {
        $self->{seen_custom_ns}++;
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    $self->_track_event(end => { ns => $ns, ln => $ln });
    return $self->SUPER::end_element($el);
}

sub characters ($self, $d) {
    my $text = $d->{Data} // '';
    $self->_track_event(chars => { len => length($text),
                                   has_ws_only => ($text =~ /^\s*$/) ? 1 : 0 })
        if length $text;
    return $self->SUPER::characters($d);
}

# ── Assertion helpers (Test2::V0 compose; DI-1 render-safe) ────────────
# Each helper returns 1 on pass, 0 on fail, and increments
# AssertionsPassed / AssertionsFailed counters for report().
#
# They intentionally take ($test_label, @args) so a future DI-1 collector
# can emit <amin:test_assert label="…" kind=pass|fail> by re-skinning this
# single call site — Test2::V0 right now, SAX dashboard later.
sub _bump ($self, $ok) {
    if ($ok) { $self->{AssertionsPassed}++ }
    else     { $self->{AssertionsFailed}++ }
    return $ok;
}

sub assert_seen_count ($self, $label, %matcher) {
    my ($kind, $ns, $ln) = delete @matcher{qw(kind ns ln)};
    my $count = 0;
    for my $ev ($self->seen->@*) {
        next if defined($kind) && $ev->{kind} ne $kind;
        next if defined($ns)   && ($ev->{ns}   // '') ne $ns;
        next if defined($ln)   && ($ev->{ln}   // '') ne $ln;
        $count++;
    }
    my $expected = delete $matcher{count} // 1;
    my $ok = ($count == $expected);
    if (defined &Test2::V0::is) {
        Test2::V0::is($count, $expected, $label);
    }
    return $self->_bump($ok);
}

sub assert_seen_some ($self, $label, %matcher) {
    $matcher{count} = undef;
    my ($kind, $ns, $ln) = delete @matcher{qw(kind ns ln)};
    my $found = 0;
    for my $ev ($self->seen->@*) {
        next if defined($kind) && $ev->{kind} ne $kind;
        next if defined($ns)   && ($ev->{ns}   // '') ne $ns;
        next if defined($ln)   && ($ev->{ln}   // '') ne $ln;
        $found = 1; last;
    }
    if (defined &Test2::V0::ok) {
        Test2::V0::ok($found, $label);
    }
    return $self->_bump($found);
}

sub assert_seen_none ($self, $label, %matcher) {
    $matcher{count} = undef;
    my ($kind, $ns, $ln) = delete @matcher{qw(kind ns ln)};
    my $found = 0;
    for my $ev ($self->seen->@*) {
        next if defined($kind) && $ev->{kind} ne $kind;
        next if defined($ns)   && ($ev->{ns}   // '') ne $ns;
        next if defined($ln)   && ($ev->{ln}   // '') ne $ln;
        $found = 1; last;
    }
    my $ok = !$found;
    if (defined &Test2::V0::ok) {
        Test2::V0::ok($ok, $label);
    }
    return $self->_bump($ok);
}

sub assert_custom_ns_seen ($self, $label) {
    my $ok = ($self->{seen_custom_ns} // 0) > 0;
    if (defined &Test2::V0::ok) {
        Test2::V0::ok($ok, $label);
    }
    return $self->_bump($ok);
}

# ── End-of-stream summary: emit counters (diagnostics under prove) ─────
# Returns true iff 0 assertions failed (useful for `$t->report || done_testing()`).
sub report ($self) {
    my $passed = $self->{AssertionsPassed} // 0;
    my $failed = $self->{AssertionsFailed} // 0;
    my $events = scalar $self->seen->@*;
    my $ok = ($failed == 0);
    if (defined &Test2::V0::diag && !$ok) {
        Test2::V0::diag(
            sprintf('%s: %d assertions (%d pass, %d fail) across %d SAX events',
                $self->label, $passed + $failed, $passed, $failed, $events)
        );
    }
    return $ok;
}

1;
