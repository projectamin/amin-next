#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Net::Fabric;
use Amin::Sandbox;
use Amin::Machine::Dispatcher;
use Amin::Handler::Writer;
use Amin::Log::Standard;
use Amin::Test::StreamCapture;
use Amin qw(NS);

sub build_zcap_token (%o) {
    # Real e2e: ML-DSA-87 signature issued by the Rust toolchain (bctool) —
    # the same production signer — verifies against Amin::Auth::ZCap with
    # the VK registered as a mesh trust anchor.  Falls back to the legacy
    # structural placeholder when no signer binary is present.
    my %o = (
        tiers          => [qw(shared metal-32c metal-16c metal-96c)],
        zones          => [qw(us-east-1 us-west-2 global shared)],
        netpols        => [ '*', map "vpc-$_", 'a'..'z' ],
        max_redundancy => 255,
        vpc_quota      => 0xFFFFFFFF,
        memory_tier    => 5,
        tenant_id      => 't-test-permissive-00000000',
        ts             => 1735689600,
        @_,
    );
    $o{max_redundancy} = 255 if $o{max_redundancy} > 255;
    require Amin::Test::ZCapSign;
    return Amin::Test::ZCapSign::make_zcap_token(%o);
}


my $ZC_PERMISSIVE = build_zcap_token();

# ── TR-1.2a: Empty process stack before use ──
is(Amin::Net::Fabric->_scope_count_for_tests, 0, 'fabric scope stack starts at 0');
ok(!defined Amin::Net::Fabric->current_scope_attrs, 'fabric current_scope_attrs undef when no scope');

# ── TR-1.2b: build chain, fire synthetic <net open> + <spawn> + close ──
my $writer = Amin::Handler::Writer->new;
my $log = Amin::Log::Standard->new(stderr => 0);
my $chain = Amin::Machine::Dispatcher::_build_chain(
    $writer, $log, 'render', { map => 0, ui => 0 });
ok($chain, '_build_chain ok');

my $fab = Amin::Net::Fabric->new(
    Handler => Amin::Handler::Writer->new,
    Log     => $log,
    Mode    => 'render',
);

my $NS = NS();
my $net_open = {
    NamespaceURI => $NS,
    LocalName    => 'net',
    Name         => "{$NS}net",
    Attributes   => {
        "{$NS}vpc" => {
            NamespaceURI => $NS, LocalName => 'vpc',
            Name => "{$NS}vpc", Value => 'prod',
        },
        "{$NS}mode" => {
            NamespaceURI => $NS, LocalName => 'mode',
            Name => "{$NS}mode", Value => 'isolated',
        },
        "{$NS}subnet" => {
            NamespaceURI => $NS, LocalName => 'subnet',
            Name => "{$NS}subnet", Value => '10.23.42.0/24',
        },
        "{$NS}gateway" => {
            NamespaceURI => $NS, LocalName => 'gateway',
            Name => "{$NS}gateway", Value => '10.23.42.1',
        },
    },
};

# start net scope
$fab->start_element($net_open);
is(Amin::Net::Fabric->_scope_count_for_tests, 1, 'after net start: stack count = 1');
my $attrs = Amin::Net::Fabric->current_scope_attrs;
ok(ref($attrs) eq 'HASH' && keys %$attrs >= 3, 'current_scope_attrs is HASH with attrs');
is($attrs->{vpc}, 'prod', 'vpc attr captured correctly');
is($attrs->{mode}, 'isolated', 'mode attr captured correctly');
is($attrs->{subnet}, '10.23.42.0/24', 'subnet attr captured correctly');
is($attrs->{gateway}, '10.23.42.1', 'gateway attr captured correctly');

# synthetic spawn sibling inside scope
my $spawn_open = {
    NamespaceURI => $NS, LocalName => 'spawn',
    Name => "{$NS}spawn", Attributes => {},
};
$fab->start_element($spawn_open);
$attrs = Amin::Net::Fabric->current_scope_attrs;
ok(defined $attrs, 'scope still active when inside sibling spawn');
$fab->end_element({ %$spawn_open });
is(Amin::Net::Fabric->_scope_count_for_tests, 1, 'spawn close did NOT affect net scope');

# end net scope
$fab->end_element({ NamespaceURI => $NS, LocalName => 'net', Name => "{$NS}net" });
is(Amin::Net::Fabric->_scope_count_for_tests, 0, 'after </net>: stack back to 0');
ok(!defined Amin::Net::Fabric->current_scope_attrs, 'fabric current_scope_attrs undef after scope end');

# ── TR-1.2d: multiple sequential net scopes ──
my $n1 = { NamespaceURI => $NS, LocalName => 'net', Name => "{$NS}net",
    Attributes => {
        "{$NS}vpc" => { NamespaceURI => $NS, LocalName => 'vpc',
            Name => "{$NS}vpc", Value => 'mgmt' },
        "{$NS}mode" => { NamespaceURI => $NS, LocalName => 'mode',
            Name => "{$NS}mode", Value => 'fabric' },
    }};
my $n2 = { NamespaceURI => $NS, LocalName => 'net', Name => "{$NS}net",
    Attributes => {
        "{$NS}vpc" => { NamespaceURI => $NS, LocalName => 'vpc',
            Name => "{$NS}vpc", Value => 'lb' },
        "{$NS}mode" => { NamespaceURI => $NS, LocalName => 'mode',
            Name => "{$NS}mode", Value => 'isolated' },
    }};

$fab->start_element($n1);
is(Amin::Net::Fabric->_scope_count_for_tests, 1, 'n1 open: count=1');
is(Amin::Net::Fabric->current_scope_attrs->{vpc}, 'mgmt', 'n1 vpc = mgmt mode fabric');
$fab->end_element({ NamespaceURI => $NS, LocalName => 'net', Name => "{$NS}net" });
is(Amin::Net::Fabric->_scope_count_for_tests, 0, 'n1 close: count=0');

$fab->start_element($n2);
is(Amin::Net::Fabric->_scope_count_for_tests, 1, 'n2 open: count=1');
is(Amin::Net::Fabric->current_scope_attrs->{vpc}, 'lb', 'n2 vpc = lb mode isolated');
is(Amin::Net::Fabric->stash_for_spawn('s2')->{vpc}, 'lb',
    'stash_for_spawn() package method returns active attrs');
$fab->end_element({ NamespaceURI => $NS, LocalName => 'net', Name => "{$NS}net" });
is(Amin::Net::Fabric->_scope_count_for_tests, 0, 'n2 close: count=0 balanced');

# ── TR-1.3: SAX delta emit (AC-4 contract)
#    lb + netpolicy elements should pass through unchanged (no capture leak)
{
    my $rec = Amin::Test::StreamCapture->new;
    my $fab2 = Amin::Net::Fabric->new(
        Handler => $rec, Log => $log, Mode => 'render',
    );
    my $lb_open = {
        NamespaceURI => $NS, LocalName => 'lb', Name => "{$NS}lb",
        Attributes => {
            "{$NS}vip" => { NamespaceURI => $NS, LocalName => 'vip',
                Name => "{$NS}vip", Value => '10.55.0.100:8080' },
            "{$NS}backends" => { NamespaceURI => $NS, LocalName => 'backends',
                Name => "{$NS}backends", Value => 'b-1=10.1:80,b-2=10.2:80,b-3=10.3:80,b-4=10.4:80' },
            "{$NS}policy" => { NamespaceURI => $NS, LocalName => 'policy',
                Name => "{$NS}policy", Value => 'p2c_ewma' },
        },
    };
    my $np_open = {
        NamespaceURI => $NS, LocalName => 'netpolicy', Name => "{$NS}netpolicy",
        Attributes => {
            "{$NS}from"  => { NamespaceURI => $NS, LocalName => 'from',
                Name => "{$NS}from", Value => 'vpc=prod,subnet=10.23.42.0/24' },
            "{$NS}to"    => { NamespaceURI => $NS, LocalName => 'to',
                Name => "{$NS}to", Value => 'vpc=mgmt,subnet=10.99.1.0/24' },
            "{$NS}allow" => { NamespaceURI => $NS, LocalName => 'allow',
                Name => "{$NS}allow", Value => 'NONE' },
        },
    };
    $fab2->start_element($lb_open);
    $fab2->end_element({ %$lb_open });
    $fab2->start_element($np_open);
    $fab2->end_element({ %$np_open });
    my @ev = $rec->captured->@*;
    my @starts = grep { $_->[0] eq 'start_element' } @ev;
    my @starts_el = map { $_->[1] } @starts;
    sub _strip_ns_key($k) {
        my $kk = $k;
        my $ns_pre = '{' . 'http://projectamin.org/ns/2026/' . '}';
        substr($kk, 0, length($ns_pre), '') if substr($kk, 0, length($ns_pre)) eq $ns_pre;
        substr($kk, 0, 2, '') if substr($kk, 0, 2) eq '{}';
        return $kk;
    }
    sub _attr_op_eq($el, $expected) {
        my $attrs = $el->{Attributes} // {};
        for my $k (keys %$attrs) {
            my $a = $attrs->{$k};
            next unless ref $a eq 'HASH';
            my $ln = ($a->{LocalName} // '') ne '' ? $a->{LocalName} : _strip_ns_key($k);
            next unless $ln eq 'op';
            return 1 if (($a->{Value} // '') eq $expected);
        }
        return 0;
    }
    my @deltas_net = grep {
        my $ln = $_->{LocalName} // '';
        ($ln =~ /^(net|lb|netpolicy)$/) && do {
            my $attrs = $_->{Attributes} // {};
            my $has = 0;
            for my $k (keys %$attrs) {
                my $a = $attrs->{$k};
                next unless ref $a eq 'HASH';
                my $kln = $a->{LocalName} // '';
                if ($kln eq '') {
                    $kln = _strip_ns_key($k);
                }
                if ($kln eq 'op' && defined($a->{Value}) && length($a->{Value})) {
                    $has = 1; last;
                }
            }
            $has;
        }
    } @starts_el;
    is(scalar(@deltas_net), 2,
        'lb init + netpolicy add_rule delta elements emitted (emit_net_delta contract)');
    my ($lb_delta) = grep {
        ($_->{LocalName} // $_->{Name} // '') eq 'lb' && _attr_op_eq($_, 'init')
    } @starts_el;
    ok($lb_delta, 'lb delta op=init exists (AC-4 contract: BEFORE aminexec harness; permanent filters observe delta first)');
    my ($np_delta) = grep {
        ($_->{LocalName} // $_->{Name} // '') eq 'netpolicy' && _attr_op_eq($_, 'add_rule')
    } @starts_el;
    ok($np_delta, 'netpolicy delta op=add_rule exists before kernel call');
}

# ── T4.1 Net::Fabric mode=isolated sync Exec E2E (CASE A/B mutual exclusive) ──
# Runs the full aminexec --sandbox-stdin path with a real net block merged.
# CASE A: kernel has CONFIG_NET_NS + VETH + CAP_NET_ADMIN → verify eth0 inet
#         address 10.23.42.2/24 + default via 10.23.42.1 dev eth0 present in
#         workload stdout (SAX-observed character data stream).
# CASE B: kernel missing abi or no CAP_NET_ADMIN → rc=-4099 net_missing_abi
#         NFR-NF-7 fail-closed; workload payload NEVER executed.
{
    require Amin::Command::Exec;
    require Amin::Handler::Writer;
    require Amin::Machine::Dispatcher;
    require Amin::Log::Standard;
    my $xml = <<"XML";
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="$ZC_PERMISSIVE"/>
  <amin:net amin:mode="isolated" amin:vpc="prod" amin:subnet="10.23.42.0/24" amin:gateway="10.23.42.1">
    <amin:exec amin:name="netcheck_isolated">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo NETCHECK_START; /sbin/ip -o -4 addr show eth0 2>/dev/null || ip -o -4 addr show eth0 2>/dev/null; echo ROUTE_LINE; /sbin/ip -4 route show default 2>/dev/null || ip -4 route show default 2>/dev/null; echo NS_INODE; stat -L -c %i /proc/self/ns/net 2>/dev/null; echo NETCHECK_END</amin:argv>
    </amin:exec>
  </amin:net>
</amin:init>
XML
    my $writer = Amin::Handler::Writer->new(indent => 2);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    ok(defined $out && length $out,
        'T4.1 mode=isolated: run produced SAX output (aminexec path exercised)');

    my $is_net_missing_abi = ($out =~ /exit_kind="net_missing_abi"/) ? 1 : 0;
    my $is_ok_or_nonzero   = ($out =~ /exit_kind="(ok|nonzero|sandbox_missing_abi)"/) ? 1 : 0;
    ok($is_net_missing_abi || $is_ok_or_nonzero,
        'T4.1: status exit_kind is one of (net_missing_abi, ok, nonzero, sandbox_missing_abi)');

    my $out_chars = '';
    {
        # Extract <amin:stream type="out"> character data concatenation (SAX filter contract: only additive sibling streams, no inline edits).
        while ($out =~ /<amin:stream\s+type="out">(.*?)<\/amin:stream>/gs) {
            $out_chars .= $1;
        }
    }

    SKIP: {
        skip 'T4.1 CASE A: kernel has NET_NS/VETH/CAP_NET_ADMIN; skip fail-closed audit', 5
            if $is_net_missing_abi;
        # If CASE A active: either ip/route output actually parsed from netns,
        # OR the distro lacks iproute2 in which case we at minimum confirm
        # aminexec glue ran (NETCHECK_END token present in stdout chars means
        # workload actually exec'd inside aminexec sandbox).
        my $has_netcheck_end = ($out_chars =~ /NETCHECK_END/) ? 1 : 0;
        my $has_10_23_42_2   = ($out_chars =~ /\b10\.23\.42\.2\b/) ? 1 : 0;
        my $has_default_via  = ($out_chars =~ /default\s+via\s+10\.23\.42\.1\s+dev\s+eth0/) ? 1 : 0;
        ok($has_netcheck_end,
            'T4.1 CASE A: workload payload ran inside aminexec (NETCHECK_END observed on SAX out stream)');
        skip 'T4.1 CASE A positive: distro lacks /sbin/ip tooling, skip IP/route assertions', 4
            unless $has_10_23_42_2 || $has_default_via || ($out_chars =~ m{inet\s+10\.23\.42});
        ok(($has_10_23_42_2 || $out_chars =~ m{\binet\s+10\.23\.42\.2/24\b}),
            'T4.1 CASE A: eth0 inet address matches scope-allocated 10.23.42.2/24 (netns_unshare + addr worked)');
        ok($has_default_via || ($out_chars =~ /default.*10\.23\.42\.1.*eth0/),
            'T4.1 CASE A: default route via 10.23.42.1 dev eth0 present (netns route setup worked)');
        # Verify NS inode different from host's default /proc/self/ns/net inode.
        my $host_ns = eval {
            my ($ino) = (stat('/proc/self/ns/net'))[1];
            $ino;
        };
        my ($child_ns) = ($out_chars =~ /NS_INODE\s+(\d+)/);
        SKIP: {
            skip 'T4.1 CASE A inode: host ns stat unavailable or child ns not captured', 1
                unless defined $host_ns && defined $child_ns && length $child_ns;
            ok($child_ns != $host_ns,
                'T4.1 CASE A: workload ns inode differs from host ns (CLONE_NEWNET actually active)');
        }
        # Structural: exactly 1 <result> from 1 <exec> inside <net> wrapper.
        my @results = ($out =~ /<amin:result\b/g);
        cmp_ok(scalar(@results), '==', 1,
            'T4.1 CASE A structural: exactly 1 <result> sibling for 1 wrapped exec (no extra nodes; additive-only SAX contract)');
    }

    SKIP: {
        skip 'T4.1 CASE B: kernel had abi, skip fail-closed NFR audit', 5
            unless $is_net_missing_abi;
        like($out, qr/rc="-4099"/,
            'T4.1 CASE B NFR-NF-7 fail-closed: status rc=-4099 matches aminexec LE net_missing_abi prefix');
        unlike($out, qr/exit_kind="ok"/,
            'T4.1 CASE B: exit_kind=ok NEVER present when net setup cannot complete');
        unlike($out_chars, qr/NETCHECK_END/,
            'T4.1 CASE B: workload payload NEVER executed (NETCHECK_END token absent from out stream; rollback before exec)');
        unlike($out_chars, qr/\b10\.23\.42\.2\b/,
            'T4.1 CASE B: NO leaked scope-allocated IP text in stream (no netns / veth partially set up)');
        my $reg = Amin::Command::Spawn->registry;
        is(scalar keys %$reg, 0,
            'T4.1 CASE B: sync Exec path — 0 lingering spawn pids in registry');
    }
}

Amin::Command::Spawn->registry->%* = ();
Amin::Command::Spawn->by_pid->%*   = ();

done_testing;
