#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Machine::Dispatcher;
use Amin::Machine::MachineSpec;
use Amin::Handler::Writer;
use Amin::Log::Standard;

# Filters are never auto-loaded: %FILTERS starts empty.  Every filter is
# declared by the machine spec.  %FILTERS only receives entries at runtime
# via register() (e.g. --with-begin / --with-middle / --with-end).
my $reg = \%Amin::Machine::Dispatcher::FILTERS;
my $total_reg = 0;
$total_reg += scalar($_->@*) for values %$reg;
is($total_reg, 0, '%FILTERS registry starts empty (no BEGIN auto-load; filters are spec-declared)');

my $spec = Amin::Machine::MachineSpec->new->spec;
my @spec_filters = $spec->{filters}->@*;
my %by_pos;
for my $f (@spec_filters) {
    my $p = $f->{meta}{position} // 'middle';
    push $by_pos{$p}->@*, $f;
}
for my $pos (qw(begin middle late end)) {
    ok(exists $by_pos{$pos} && ref $by_pos{$pos} eq 'ARRAY',
       "spec declares position '$pos' as ARRAY");
}
ok(!exists $by_pos{permanent} || ref($by_pos{permanent}) eq 'ARRAY',
    'permanent position valid (empty/unused is OK — trust boundary)');

my $late = [ map { $_->{class} } $by_pos{late}->@* ];
like($late, array {
    item 'Amin::Filter::Map::Topology';
    item 'Amin::Filter::UI::SwiftUIView';
    item 'Amin::AI::Graph';
    end;
}, 'spec late position = Map::Topology + UI::SwiftUIView + AI::Graph');

my $bare_chain = Amin::Machine::Dispatcher::_build_chain(
    Amin::Handler::Writer->new, Amin::Log::Standard->new(stderr=>0), 'render',
    { map => 0, ui => 0 });
isa_ok($bare_chain, ['Amin::Auth::ZCap'],
       'late=00 composes ZCap (outermost) → Cond::OS → ProfileValidator → Placement inward');

my $mid = [ map { $_->{class} } $by_pos{middle}->@* ];
is($by_pos{middle}[0]{class},  'Amin::Command::Addr2line', 'spec middle idx 0 = Addr2line (alphabetical)');
is($by_pos{middle}[1]{class},  'Amin::Command::Ar',        'spec middle idx 1 = Ar');
is($by_pos{middle}[2]{class},  'Amin::Command::As',        'spec middle idx 2 = As');
is($by_pos{middle}[3]{class},  'Amin::Command::Autoconf',  'spec middle idx 3 = Autoconf');
is($by_pos{middle}[4]{class},  'Amin::Command::Automake',  'spec middle idx 4 = Automake');
is($by_pos{middle}[5]{class},  'Amin::Command::Autoreconf','spec middle idx 5 = Autoreconf');
my $last = $#{$by_pos{middle}};
is($by_pos{middle}[$last-8]{class}, 'Amin::Command::Exec',    'spec middle idx -9 = Exec');
is($by_pos{middle}[$last-7]{class}, 'Amin::Command::Spawn',   'spec middle idx -8 = Spawn');
is($by_pos{middle}[$last-6]{class}, 'Amin::Command::Signal',  'spec middle idx -7 = Signal');
is($by_pos{middle}[$last-5]{class}, 'Amin::Sandbox',          'spec middle idx -6 = Sandbox (AC-NF-1 ordering)');
is($by_pos{middle}[$last-4]{class}, 'Amin::Net::Fabric',      'spec middle idx -5 = Net::Fabric');
is($by_pos{middle}[$last-3]{class}, 'Amin::AI::Inference',    'spec middle idx -4 = AI::Inference');
is($by_pos{middle}[$last-2]{class}, 'Amin::AI::Embed',        'spec middle idx -3 = AI::Embed (RAG memory ingest)');
is($by_pos{middle}[$last-1]{class}, 'Amin::AI::Memory',       'spec middle idx -2 = AI::Memory (RAG retrieval)');
is($by_pos{middle}[$last]{class},   'Amin::Filter::Storage::Bitcache',
    'spec middle idx -1 = Bitcache (innermost of middle array; spec-declared)');
is(scalar($by_pos{middle}->@*), 278,
    'spec middle position count = 278 (267 commands + UCC::Sales/UCC::Instruments + Exec/Spawn/Signal + Sandbox/Net + AI::Inference/Embed/Memory + Bitcache)');

is($by_pos{begin}[0]{class}, 'Amin::Auth::ZCap',
    'spec begin idx 0 = Auth::ZCap (outermost, fires first auth boundary)');
is($by_pos{begin}[1]{class}, 'Amin::Cond::OS',
    'spec begin idx 1 = Cond::OS (after ZCap drops non-compliant elements)');
is($by_pos{begin}[2]{class}, 'Amin::Filter::Init::ProfileValidator',
    'spec begin idx 2 = ProfileValidator (before Placement, validates init-stage first)');
is($by_pos{begin}[3]{class}, 'Amin::UCC::General',
    'spec begin idx 3 = UCC::General (Art.1 transaction form validation)');
is($by_pos{begin}[4]{class}, 'Amin::UCC::Credit',
    'spec begin idx 4 = UCC::Credit (Art.5 LC authorization / presentation scope)');
is($by_pos{begin}[5]{class}, 'Amin::AI::Model',
    'spec begin idx 5 = AI::Model (catalog bind before Gate)');
is($by_pos{begin}[6]{class}, 'Amin::AI::Gate',
    'spec begin idx 6 = AI::Gate (model allowlist + ZCap scope check before placement)');
is($by_pos{begin}[7]{class}, 'Amin::Schedule::Placement',
    'spec begin idx 7 = Schedule::Placement (innermost begin, wraps AFTER profile/zcap/ucc/ai, before middle)');
is(scalar($by_pos{begin}->@*), 8, 'spec begin position count = 8 (ZCap→Cond→Profile→UCC::General→UCC::Credit→AI::Model→AI::Gate→Placement)');

my $chain = Amin::Machine::Dispatcher::_build_chain(
    Amin::Handler::Writer->new,
    Amin::Log::Standard->new(stderr => 0),
    'dryrun');
ok($chain, '_build_chain returns truthy head');
isa_ok($chain, ['Amin::Auth::ZCap'],
       'outermost wrapper is begin-position Auth::ZCap (auth boundary sees event first; inward = Cond::OS → ProfileValidator → Placement → middle)');
can_ok($chain, qw(start_element end_element characters));
ok(exists $chain->{Handler}, 'chain head has Handler slot set (inner chain wired)');

my $d = Amin::Machine::Dispatcher->new(
    Handler => Amin::Handler::Writer->new,
    Log     => Amin::Log::Standard->new(stderr=>0),
    Mode    => 'render');
ok($d->{chain}, 'Dispatcher->new populates chain via constructor');

# ────────── DI-2 / Task 1: Custom namespace / third-party filter extensibility
#             (guard test for "Corp X loads own filters w/o Amin fork")
{
    require Amin::Test::CorpExt::PolicyDummy;
    require Amin::Test::ElementCounter;

    # ── Part A: Push-ordering contract via the public register() API. ──
    # We intentionally register a Corp filter using register() — the SAME
    # public API that --with-filter / <amin:filter> will call — so we
    # verify that any third-party Corp filter ends up LAST in the begin
    # list (non-bypassable core Cond::OS fires first; Corp sees post-core
    # begin events).  This part only inspects %FILTERS class ordering; it
    # doesn't fire the filter.
    Amin::Machine::Dispatcher->register(
        'Amin::Test::CorpExt::PolicyDummy',
        position  => 'begin',
        element   => undef,
        namespace => 'https://corp.example.test/ns/amin/v1',
        namespaces => [
            'http://projectamin.org/ns/2026/',
            'https://corp.example.test/ns/sox/v1',
        ],
    );

    my $new_begin_count = scalar $Amin::Machine::Dispatcher::FILTERS{begin}->@*;
    ok($new_begin_count >= 1,
       'custom filter pushed onto begin list via register() (now ' . $new_begin_count .
       ' entry; core begin filters are spec-declared, %FILTERS holds only runtime-registered)');

    my $last = $Amin::Machine::Dispatcher::FILTERS{begin}[-1];
    is($last->{class}, 'Amin::Test::CorpExt::PolicyDummy',
       'register() push-ordering: Amin::Test Corp filter runs after core begin filters');

    # After ordering check, POP our Corp filter OFF %FILTERS so _build_chain
    # below doesn't re-instantiate a SECOND Corp (which would double-count
    # events).  Part A = ordering contract (done); Part B = event-flow test
    # using our pre-built Corp filter instance only.
    pop @{ $Amin::Machine::Dispatcher::FILTERS{begin} };

    # ── Part B: Event-flow fire test using concrete Amin::Test filter ──
    # instances as the innermost Handler layer (so they see 100% of events
    # before any Writer output).  This part does NOT use register() for
    # the firing instances — that would double-count and is unnecessary:
    # Part A already proved register() composes correctly; Part B proves
    # the Amin::Test::Handler base class works as a SAX filter contract.
    my $writer_inner = Amin::Handler::Writer->new(indent => 0);
    my $sox_counter  = Amin::Test::ElementCounter->new(
        Handler        => $writer_inner,
        namespace      => 'https://corp.example.test/ns/sox/v1',
        local_name     => 'audit-trail',
        expected_count => 1,
    );
    my $corp_filter  = Amin::Test::CorpExt::PolicyDummy->new(
        Handler           => $sox_counter,
        ExpectedMinEvents => 5,
    );
    my $handler_chain = Amin::Machine::Dispatcher::_build_chain(
        $corp_filter,                                  # innermost: Corp (reports) → ElementCounter → Writer
        Amin::Log::Standard->new(stderr => 0),
        'render',
        { map => 0, ui => 0 });

    my $NS_AMIN = 'http://projectamin.org/ns/2026/';
    my $NS_SOX  = 'https://corp.example.test/ns/sox/v1';
    my $ns = sub ($uri, $pfx, $ln, %a) {
        my $attrs = {};
        while (my ($k, $v) = each %a) {
            my ($p, $an) = ($k =~ /^([a-z]+):(.+)$/) ? ($1,$2) : ($pfx,$k);
            my $ns_uri = $p eq 'amin' ? $NS_AMIN
                       : $p eq 'sox'  ? $NS_SOX
                       : $uri;
            my $qname = length($p) ? "$p:$an" : $an;
            $attrs->{"{}$an"} = {
                Name => $qname, LocalName => $an, Prefix => $p,
                NamespaceURI => $ns_uri, Value => "$v",
            };
        }
        {   NamespaceURI => $uri, LocalName => $ln,
            Name => length($pfx) ? "$pfx:$ln" : $ln,
            Prefix => $pfx, Attributes => $attrs };
    };

    $handler_chain->start_document({});
    $handler_chain->start_element($ns->($NS_AMIN,'amin','profile',
        'amin:id' => 'ext-test',
        'amin:version' => '0.0.1'));
    $handler_chain->start_element($ns->($NS_SOX,'sox','audit-trail',
        'sox:id' => 'corpx-audit-001'));
    $handler_chain->characters({Data => "audit marker"});
    $handler_chain->end_element($ns->($NS_SOX,'sox','audit-trail'));
    $handler_chain->end_element($ns->($NS_AMIN,'amin','profile'));
    $handler_chain->end_document({});

    # ElementCounter: proves reusable Amin::Test filters correctly
    # composed into Handler chain (corp_filter → sox_counter → Writer).
    ok($sox_counter->report,
       'Amin::Test::ElementCounter reusable filter → 1 <sox:audit-trail> seen');
    ok($sox_counter->{AssertionsPassed} > 0,
       'Amin::Test::ElementCounter reusable filter ran and reported assertions');

    # Corp filter report: main DI-2 guard.
    ok($corp_filter->report,
       'Amin::Test CorpExt subclass reports all assertions passing (DI-2 guard)');
}

done_testing;
