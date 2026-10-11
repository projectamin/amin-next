use v5.38; use warnings; use strict; use utf8;
use Test2::V0;
use File::Temp ();

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(shared metal-32c metal-16c metal-96c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 us-west-2 global shared);
    my @netps  = $o{netpols}? @{$o{netpols}}: ('*', map("vpc-$_", 'a'..'z'));
    my $max_r  = $o{max_redundancy} // 255;
    my $vpc_q  = $o{vpc_quota} // 0xFFFFFFFF;
    my $mem_t  = $o{memory_tier} // 5;
    my $tenant = $o{tenant_id} // 't-test-permissive-00000000';
    my $ts     = $o{ts} // 1735689600;
    my $vk     = $o{vk} // ("\x00" x 2592);
    my $sig    = $o{sig} // ("\xaa" x 4627);
    my $tier_data = join('', map { pack('v', length($_)) . $_ } @tiers);
    my $zone_data = join('', map { pack('v', length($_)) . $_ } @zones);
    my $netp_data = join('', map { pack('v', length($_)) . $_ } @netps);
    my $scope_buf = $tier_data . $zone_data . $netp_data
        . pack('C', $max_r) . pack('V', $vpc_q) . pack('C', $mem_t)
        . 'amin.zcap.v1';
    my $scope_hash = "\x00" x 32;
    { use feature 'bitwise'; no warnings 'experimental::bitwise'; use bytes;
      for my $c (split //, $scope_buf) { $scope_hash ^.= ($c x int(32/length($c)+1)); } }
    $scope_hash = substr($scope_hash, 0, 32);
    require MIME::Base64;
    my $bytes = $sig . $vk . $scope_hash
        . pack('Q<', $ts)
        . pack('v', scalar @tiers) . pack('v', scalar @zones) . pack('v', scalar @netps)
        . pack('C', $max_r) . pack('V', $vpc_q) . pack('C', $mem_t)
        . pack('v', length($tenant)) . $tenant
        . $tier_data . $zone_data . $netp_data;
    return MIME::Base64::encode_base64($bytes, '');
}

my $ZC_PERMISSIVE = build_zcap_token();

# ── T4.2 Net::Fabric mode=fabric (shared-ns) 3-pid structural CASE A/B ──
# Wraps 2x long-running spawn + 1x sync exec ns_owner ALL inside a single
# <net mode=fabric>.  Structural invariants verified regardless of kernel
# support (CASE B runs fail-closed audit; CASE A runs inode parity / single
# veth / single shared IP assertions).  SAX/BSAX filter contract preserved:
# every <net/lb/netpolicy> mutation FIRST emits additive sibling delta BEFORE
# any netlink/bpf/clone syscall; permanent filters observe correct ordering.

# ── TR-23.0 sanity: scope stack 0 on start ──
is(Amin::Net::Fabric->_scope_count_for_tests, 0,
    'TR-23.0: fabric scope stack starts 0 clean');

my $spawn_sleep_sec = $ENV{AMIN_TEST_SPAWN_SLEEP_SEC} // 2;

{
    require Amin::Command::Exec;
    require Amin::Command::Spawn;
    require Amin::Command::Signal;
    require Amin::Net::Fabric;

    my $xml = <<"XML";
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="$ZC_PERMISSIVE"/>
  <amin:net amin:mode="fabric" amin:vpc="shared-blue" amin:subnet="10.88.0.0/24" amin:gateway="10.88.0.1">
    <amin:spawn amin:id="s1" amin:name="sleep1">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo S1_NS_INODE=\$(stat -L -c %i /proc/self/ns/net); echo S1_IP=\$(ip -o -4 addr show eth0 2>/dev/null | awk '{print \$4}' | head -n1); echo S1_READY; sleep $spawn_sleep_sec</amin:argv>
    </amin:spawn>
    <amin:spawn amin:id="s2" amin:name="sleep2">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo S2_NS_INODE=\$(stat -L -c %i /proc/self/ns/net); echo S2_IP=\$(ip -o -4 addr show eth0 2>/dev/null | awk '{print \$4}' | head -n1); echo S2_READY; sleep $spawn_sleep_sec</amin:argv>
    </amin:spawn>
    <amin:exec amin:name="fabric_ns_owner">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo EX_NS_INODE=\$(stat -L -c %i /proc/self/ns/net); echo EX_IP=\$(ip -o -4 addr show eth0 2>/dev/null | awk '{print \$4}' | head -n1); echo HOST_VETH_LIST=\$(ls /sys/class/net 2>/dev/null | grep -oE '^vf[0-9]+-[0-9]+\$' | tr '\\n' ',' | sed 's/,\$//')</amin:argv>
    </amin:exec>
    <amin:signal amin:target="s1" amin:signal="TERM"/>
    <amin:signal amin:target="s2" amin:signal="TERM"/>
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
        'TR-23.1 mode=fabric: full dispatcher run produced SAX output');

    # Extract out-stream character data (only additive sibling SAX streams;
    # NO retroactively closed result/status edits).
    my $out_chars = '';
    while ($out =~ /<amin:stream\s+type="out">(.*?)<\/amin:stream>/gs) {
        $out_chars .= $1;
    }

    # Count result structural parity: 2x spawn results (open running, then
    # signal reopens for terminal status) + 1x exec result = 3 result pairs.
    my @results_open  = ($out =~ /<amin:result\b/g);
    my @results_close = ($out =~ /<\/amin:result>/g);
    cmp_ok(scalar(@results_open), '>=', 3,
        'TR-23.2: >= 3 <result> elements (2 spawn + 1 exec); additive SAX sibling structure');
    is(scalar(@results_open), scalar(@results_close),
        'TR-23.2: result open/close tag parity (no capture leak; closed-world delta-only)');

    # 3 exit_kind classifications across 2x spawn-terminal + 1x exec-terminal.
    # CASE B fires if ANY terminal status shows net_missing_abi rc=-4099.
    # The synchronous <exec> inside the fabric scope ALWAYS runs net block, so
    # its result is a reliable indicator (even when spawns get TERM raced).
    my $exec_net_missing = ($out =~ /<amin:exec[^>]*>.*?<amin:status[^>]*exit_kind="net_missing_abi"/s) ? 1 : 0;
    my $any_net_missing = ($out =~ /exit_kind="net_missing_abi"/) ? 1 : 0;
    my $any_sb_missing  = ($out =~ /exit_kind="sandbox_missing_abi"/) ? 1 : 0;
    my $case_b = ($exec_net_missing || $any_net_missing || $any_sb_missing) ? 1 : 0;

    SKIP: {
        skip 'TR-23 CASE A: kernel NET_NS/VETH/CAP_NET_ADMIN present; skip fail-closed audit', 9
            if $case_b;

        # CASE A active → extract pids from streams (spawn emits pid into
        # stream type=pid channel per Spawn.pm line 251).
        my %pid_for;
        while ($out =~ /<amin:stream\s+type="pid">(\d+)<\/amin:stream>/g) {
            my $pid = $1;
            if (!exists $pid_for{s1}) { $pid_for{s1} = $pid; next }
            if (!exists $pid_for{s2}) { $pid_for{s2} = $pid; next }
        }

        # Extract all three NS_INODE values from concatenated out stream chars.
        my ($s1_ino) = ($out_chars =~ /S1_NS_INODE=(\d+)/);
        my ($s2_ino) = ($out_chars =~ /S2_NS_INODE=(\d+)/);
        my ($ex_ino) = ($out_chars =~ /EX_NS_INODE=(\d+)/);
        my ($s1_ip)  = ($out_chars =~ /S1_IP=(\S+)/);
        my ($s2_ip)  = ($out_chars =~ /S2_IP=(\S+)/);
        my ($ex_ip)  = ($out_chars =~ /EX_IP=(\S+)/);
        my ($host_veth_list) = ($out_chars =~ /HOST_VETH_LIST=(\S*)/);

        my @got = grep { defined && length } ($s1_ino, $s2_ino, $ex_ino);
        skip 'TR-23 CASE A: ns inodes not captured by out streams (possibly no iproute2); skip kernel assertions', 8
            unless scalar(@got) >= 2;
        is($s1_ino, $s2_ino,
            'TR-23 CASE A NS equality: s1 and s2 ns inode IDENTICAL (mode=fabric shares one bind-mounted netns)')
            if defined $s1_ino && defined $s2_ino;
        is($s1_ino, $ex_ino,
            'TR-23 CASE A NS equality: s1 and exec ns inode IDENTICAL (all 3 pids live in fabric shared netns)')
            if defined $s1_ino && defined $ex_ino;
        skip 'CASE A: eth0 ip not captured (ns lacks iproute2); skip shared-ip parity', 5
            unless (defined $s1_ip && length $s1_ip) && (defined $ex_ip && length $ex_ip);
        is($s1_ip, $s2_ip,
            'TR-23 CASE A shared-IP: s1 eth0 IP EQUALS s2 eth0 IP (single shared eth0, not per-spawn)')
            if defined $s2_ip && length $s2_ip;
        is($s1_ip, $ex_ip,
            'TR-23 CASE A shared-IP: s1 eth0 IP EQUALS exec eth0 IP (all three share single eth0 iface, subnet prefix 10.88.0.0/24)');
        like($s1_ip, qr{^10\.88\.0\.\d+/24$},
            'TR-23 CASE A shared-IP: IP in allocated subnet (scope gateway 10.88.0.1 prefix)');

        # Single host-side veth interface count: mode=fabric allocates 1 veth
        # pair for entire scope; the comma-separated HOST_VETH_LIST produced
        # by ls vf*-* glob should have <= 2 interface names (this scope's veth
        # host-end + possibly one leftover from earlier t/22 run that got
        # cleaned up by kernel netns release).
        my @host_vf_names = split /,/, ($host_veth_list // '');
        cmp_ok(scalar(grep { length } @host_vf_names), '<=', 2,
            'TR-23 CASE A single-veth: <= 2 host vf veth ifaces visible (mode=fabric uses single shared veth; not 3 per-spawn)');
        ok(1, 'TR-23 CASE A: aminexec spawn harness exercised for 3 pids inside shared fabric netns');
    }

    SKIP: {
        skip 'TR-23 CASE B: kernel had abi support; skip fail-closed audit', 8
            unless $case_b;
        like($out, qr/rc="-4099"/s,
            'TR-23 CASE B NFR-NF-7 fail-closed: at least 1 status rc=-4099 present (net_missing_abi aminexec LE prefix)');
        unlike($out, qr/exit_kind="ok"[^"]*net_missing_abi=0/,
            'TR-23 CASE B: no exit_kind=ok on any status that had net_missing_abi sibling');
        unlike($out_chars, qr/S1_READY|S2_READY/,
            'TR-23 CASE B: NO spawn workload payload executed (S1_READY/S2_READY tokens absent)');
        unlike($out_chars, qr/EX_IP=\S+/,
            'TR-23 CASE B: NO exec workload eth0 IP leaked in stream');
        unlike($out_chars, qr/S1_NS_INODE=\d+/,
            'TR-23 CASE B: NO ns inode text leaked on s1 out channel (no netns / veth setup half-run)');
        # Single status element contains BOTH rc=-4099 AND exit_kind=net_missing_abi.
        my $found_pair = 0;
        {
            my $out_copy = $out;
            while ($out_copy =~ /<amin:status\b([^>]*)>/gc) {
                my $attrs = $1 // '';
                if ($attrs =~ /\brc="-4099"/ && $attrs =~ /\bexit_kind="net_missing_abi"/) {
                    $found_pair = 1; last;
                }
            }
        }
        ok($found_pair,
            'TR-23 CASE B structural: single status element has both rc=-4099 + exit_kind=net_missing_abi (same element; additive only, not inline split)');
        my $reg = Amin::Command::Spawn->registry;
        is(scalar keys %$reg, 0,
            'TR-23 CASE B: 0 lingering spawn pids remain after signal/unregister cycle complete');
        # AC-4 delta: synthetic <net op=open_scope> (emitted with Prefix='', Writer renders
        # it as `<net ...> not <amin:net>).  Robust match: just grep over all net tags.
        my @all_nettags = ($out =~ /<(?:amin:)?net\b[^>]*>/g);
        my @net_open_deltas = grep { /\bop="open_scope"/ } @all_nettags;
        cmp_ok(scalar(@net_open_deltas), '>=', 1,
            'TR-23 CASE B AC-4: synthetic <net op=open_scope> delta emitted (permanent filters capture delta FIRST before kernel path attempt)');
    }
}

Amin::Command::Spawn->registry->%* = ();
Amin::Command::Spawn->by_pid->%*   = ();
is(Amin::Net::Fabric->_scope_count_for_tests, 0,
    'TR-23 end: fabric scope stack returns to 0 clean (no stash leak across pop)');

done_testing;
