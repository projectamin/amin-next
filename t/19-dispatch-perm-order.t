#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Machine::Dispatcher;
use Amin::Handler::Writer;
use Amin::Log::Standard;

require Amin::Test::Dispatch::DropBegin;
require Amin::Test::Dispatch::CountPerm;
require Amin::Test::Dispatch::TraceEnd;
require Amin::Test::Dispatch::TraceLate;

my $NS_AMIN = 'http://projectamin.org/ns/2026/';

# ── Helper: build a SAX element hash with plain attrs ────────────────────────
my $el = sub ($ln, %a) {
    my $attrs = {};
    while (my ($k, $v) = each %a) {
        $attrs->{"{}$k"} = {
            Name => $k, LocalName => $k, Prefix => '',
            NamespaceURI => '', Value => "$v",
        };
    }
    +{  NamespaceURI => $NS_AMIN, LocalName => $ln,
        Name         => "amin:$ln", Prefix => 'amin',
        Attributes   => $attrs };
};

# ── Subtest 1: permanent (trust boundary) sees events that begin DROPS ───────
subtest 'TR-2.1 permanent sees dropped events' => sub {
    # ── 1a. Push-ordering contract: register via public API, assert order. ──
    Amin::Machine::Dispatcher->register(
        'Amin::Test::Dispatch::CountPerm',
        position => 'permanent', element => undef, namespace => $NS_AMIN);
    Amin::Machine::Dispatcher->register(
        'Amin::Test::Dispatch::DropBegin',
        position => 'begin', element => undef, namespace => $NS_AMIN);

    # ── 1b. Instantiate concrete instances as innermost Handler layer. ──
    #     Pop off register() class entries first so _build_chain doesn't
    #     create SECOND instances of them (prevents double-counting).
    #     Chain order from parser-inbound to writer:
    #       CountPerm (permanent-test → fires first, sees ALL events)
    #       → DropBegin (begin-test → fires after permanent, drops)
    #       → Writer (sink, renders surviving events)
    my $writer_innermost = Amin::Handler::Writer->new;
    my $countperm = Amin::Test::Dispatch::CountPerm->new(
        Handler                 => undef,   # set below via DropBegin → writer
        expected_starts         => 5,
        expected_ends           => 5,
        expected_min_chars_bytes=> length('this-will-be-dropped'),
    );
    my $dropbegin = Amin::Test::Dispatch::DropBegin->new(
        drop_local_name => 'drop-me',
        Handler         => $writer_innermost,
    );
    # CountPerm (permanent position) wraps DropBegin (begin position)
    $countperm->Handler($dropbegin);
    my $chain_head;
    {   # Wrap the chain build in a local scope — pop register entries, build
        # with our concrete CountPerm → DropBegin → Writer as innermost $head.
        my @saved_perm = splice @{ $Amin::Machine::Dispatcher::FILTERS{permanent} }, -1;
        my @saved_beg  = splice @{ $Amin::Machine::Dispatcher::FILTERS{begin} }, -1;
        $chain_head = Amin::Machine::Dispatcher::_build_chain(
            $countperm,
            Amin::Log::Standard->new(stderr => 0),
            'render',
            { map => 0, ui => 0 });
        # Restore register entries (so ordering subtests elsewhere still work
        # even though we drive the firing instances manually here).
        push $Amin::Machine::Dispatcher::FILTERS{permanent}->@*, @saved_perm;
        push $Amin::Machine::Dispatcher::FILTERS{begin}->@*, @saved_beg;
    }

    # 5 start_elements total: profile, drop-me, rc, drop-me, host
    # After begin drops: profile, rc, host (3 survive)
    # permanent MUST see all 5. If permanent were inside begin, it would see 3.
    $chain_head->start_document({});
    $chain_head->start_element($el->('profile', id => 'p1'));
      $chain_head->start_element($el->('drop-me', reason => 'veto-1'));
        $chain_head->characters({Data => 'this-will-be-dropped'});
      $chain_head->end_element($el->('drop-me'));
      $chain_head->start_element($el->('rc', kind => 'machine', id => 'm0'));
      $chain_head->end_element($el->('rc'));
      $chain_head->start_element($el->('drop-me', reason => 'veto-2'));
      $chain_head->end_element($el->('drop-me'));
      $chain_head->start_element($el->('host', hostname => 'db0'));
      $chain_head->end_element($el->('host'));
    $chain_head->end_element($el->('profile'));
    $chain_head->end_document({});

    is($countperm->{start_count}, 5, 'permanent saw all 5 start_element incl. drop-me');
    is($countperm->{end_count},   5, 'permanent saw all 5 end_element incl. drop-me');
    cmp_ok($countperm->{chars_sum_bytes}, '>=', length('this-will-be-dropped'),
           'permanent saw dropped character payload');
    is($dropbegin->{drop_count}, 2, 'begin actually dropped 2 (stress guard: drop is real)');
};

# ── Subtest 2: end sees events AFTER late (so it observes late-injections) ───
subtest 'TR-2.2 end sees after late injections' => sub {
    # Clean up previous subtest registrations
    $Amin::Machine::Dispatcher::FILTERS{permanent} = [];
    $Amin::Machine::Dispatcher::FILTERS{begin}     = [];
    $Amin::Machine::Dispatcher::FILTERS{late}      = [
        grep { $_->{class} !~ /^Amin::Test::Dispatch::/ }
             @{ $Amin::Machine::Dispatcher::FILTERS{late} // [] }
    ];
    $Amin::Machine::Dispatcher::FILTERS{end}       = [
        grep { $_->{class} !~ /^Amin::Test::Dispatch::/ }
             @{ $Amin::Machine::Dispatcher::FILTERS{end} // [] }
    ];

    # ── 2a. Push-ordering contract via register() public API. ──
    Amin::Machine::Dispatcher->register(
        'Amin::Test::Dispatch::TraceLate',
        position => 'late', element => undef, namespace => $NS_AMIN);
    Amin::Machine::Dispatcher->register(
        'Amin::Test::Dispatch::TraceEnd',
        position => 'end', element => undef, namespace => $NS_AMIN);

    # ── 2b. Concrete instances as Handler (pop register entries before build). ──
    #     Chain from parser-inbound to writer:
    #       TraceLate (position=late → fires earlier, injects synth AFTER every non-synth start)
    #       → TraceEnd (position=end → fires after, sees profile then injected synth)
    #       → Writer (sink)
    my $writer_inner = Amin::Handler::Writer->new;
    my $trace_end = Amin::Test::Dispatch::TraceEnd->new(Handler => $writer_inner);
    my $trace_late = Amin::Test::Dispatch::TraceLate->new(Handler => $trace_end);
    my $chain_head;
    {
        my @saved_late = splice @{ $Amin::Machine::Dispatcher::FILTERS{late} }, -1;
        my @saved_end  = splice @{ $Amin::Machine::Dispatcher::FILTERS{end} },  -1;
        $chain_head = Amin::Machine::Dispatcher::_build_chain(
            $trace_late,
            Amin::Log::Standard->new(stderr => 0),
            'render',
            { map => 0, ui => 0 });
        push $Amin::Machine::Dispatcher::FILTERS{late}->@*, @saved_late;
        push $Amin::Machine::Dispatcher::FILTERS{end}->@*, @saved_end;
    }

    # Single element profile.  TraceLate injects 1 'late-synth' after profile start.
    # So TraceEnd should see sequence: [profile, ''] → [late-synth, 'LATE_INJECTED']
    $chain_head->start_document({});
    $chain_head->start_element($el->('profile', id => 'p2'));
    $chain_head->end_element($el->('profile'));
    $chain_head->end_document({});

    is($trace_late->{injected_count}, 1, 'late filter injected 1 synth (stress guard)');

    my $synth_count = $trace_end->trace_pairs_count(
        ln => 'late-synth', marker => 'LATE_INJECTED');
    cmp_ok($synth_count, '>=', 1,
           'end observed late-injected late-synth element (end runs AFTER late)');

    my $p_idx = $trace_end->trace_first_index(ln => 'profile',    marker => '');
    my $s_idx = $trace_end->trace_first_index(ln => 'late-synth', marker => 'LATE_INJECTED');
    ok(defined($p_idx) && defined($s_idx) && $p_idx < $s_idx,
       'end observed profile THEN late-synth (linear order confirms late→end flow)');
};

done_testing;
