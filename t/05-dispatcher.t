#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Machine::Dispatcher;
use Amin::Handler::Writer;
use Amin::Log::Standard;

my $reg = \%Amin::Machine::Dispatcher::FILTERS;
for my $pos (qw(begin middle late)) {
    ok(exists $reg->{$pos} && ref $reg->{$pos} eq 'ARRAY',
       "registry position '$pos' populated as ARRAY");
}
ok(ref($reg->{permanent} // []) eq 'ARRAY', 'permanent position valid (empty is OK)');
ok(ref($reg->{end}       // []) eq 'ARRAY', 'end position valid       (empty is OK)');

my $late = [ map { $_->{class} } $reg->{late}->@* ];
like($late, array {
    item 'Amin::Filter::Map::Topology';
    item 'Amin::Filter::UI::SwiftUIView';
    end;
}, 'late position = Map::Topology + UI::SwiftUIView');

my $bare_chain = Amin::Machine::Dispatcher::_build_chain(
    Amin::Handler::Writer->new, Amin::Log::Standard->new(stderr=>0), 'render',
    { map => 0, ui => 0 });
isa_ok($bare_chain, ['Amin::Auth::ZCap'],
       'late=00 composes ZCap (outermost) → Cond::OS → ProfileValidator → Placement inward');

my $mid = [ map { $_->{class} } $reg->{middle}->@* ];
is($reg->{middle}[0]{class},  'Amin::Command::Addr2line', 'middle idx 0 = Addr2line (alphabetical)');
is($reg->{middle}[1]{class},  'Amin::Command::Ar',        'middle idx 1 = Ar');
is($reg->{middle}[2]{class},  'Amin::Command::As',        'middle idx 2 = As');
is($reg->{middle}[3]{class},  'Amin::Command::Autoconf',  'middle idx 3 = Autoconf');
is($reg->{middle}[4]{class},  'Amin::Command::Automake',  'middle idx 4 = Automake');
is($reg->{middle}[5]{class},  'Amin::Command::Autoreconf','middle idx 5 = Autoreconf');
my $last = $#{$reg->{middle}};
is($reg->{middle}[$last-5]{class}, 'Amin::Command::Exec',    'middle idx -6 = Exec');
is($reg->{middle}[$last-4]{class}, 'Amin::Command::Spawn',   'middle idx -5 = Spawn');
is($reg->{middle}[$last-3]{class}, 'Amin::Command::Signal',  'middle idx -4 = Signal');
is($reg->{middle}[$last-2]{class}, 'Amin::Sandbox',          'middle idx -3 = Sandbox (AC-NF-1 ordering)');
is($reg->{middle}[$last-1]{class}, 'Amin::Net::Fabric',      'middle idx -2 = Net::Fabric');
is($reg->{middle}[$last]{class},   'Amin::Filter::Storage::Bitcache',
    'middle idx -1 = Bitcache (innermost of middle array)');
is(scalar($reg->{middle}->@*), 273,
    'middle position count = 273 (267 commands + Exec/Spawn/Signal + Sandbox/Net/Bitcache)');

is($reg->{begin}[0]{class}, 'Amin::Auth::ZCap',
    'begin idx 0 = Auth::ZCap (outermost, fires first auth boundary)');
is($reg->{begin}[1]{class}, 'Amin::Cond::OS',
    'begin idx 1 = Cond::OS (after ZCap drops non-compliant elements)');
is($reg->{begin}[2]{class}, 'Amin::Filter::Init::ProfileValidator',
    'begin idx 2 = ProfileValidator (before Placement, validates init-stage first)');
is($reg->{begin}[3]{class}, 'Amin::Schedule::Placement',
    'begin idx 3 = Schedule::Placement (innermost begin, wraps AFTER profile/zcap, before middle)');
is(scalar($reg->{begin}->@*), 4, 'begin position count = 4 (AC-14.1 Placement idx3 — wrap chain: ZCap→Cond→Profile→Placement)');

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
    ok($new_begin_count >= 4,
       'custom filter pushed onto begin list (now ' . $new_begin_count .
       ' entries, ZCap + Cond::OS + ProfileValidator + Placement + CorpExt via Amin::Test subclass)');

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
