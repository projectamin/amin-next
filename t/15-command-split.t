#!/usr/bin/env perl
# t/15-command-split.t — Task 10: Exec / Spawn / Signal split surface.
#
# Subtests:
#   TR-10.1: Spawn a long-running sleep 15 via Dispatcher (mode=run).  After
#           100ms parse intermediate output: MUST have <result kind=running>
#           with pid attr populated, MUST NOT contain any <status> yet
#           (spawn never emits status on its own).  Then deliver SIGTERM via
#           Command::Signal, re-run parse: <status> present with
#           exit_kind=signal rc=-15 kind=error duration populated.
#
#   TR-10.2: pair-count parity (lifecycle-aware).  Build a profile with
#           (a) 3 short Execs, (b) 2 Spawn+Signal pairs.  Final rendered XML:
#           - 7 <result> total (3 echo + 2 spawn + 2 signal).
#           - 5 <status> total: every Exec result carries 1 status; every
#             Signal result carries 1 status (Signal owns the TERMINAL status
#             for the Spawn it reaped — that status lives in the Signal's
#             own result wrapper, NOT inside the original Spawn result,
#             because SAX streaming already closed the Spawn result tag
#             before the Signal element was ever reached).
#           - Spawn results have 0 <status> children: by design, a live
#             spawn never self-terminates its SAX result; Signal does.
#           - Status elements that do exist are DIRECT children of their
#             result, and terminal (no stream elements leak after a status
#             inside the same result).
#
#   Bonus: Exec in mode=dryrun → <result kind=dryrun>; no spawn.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;
require Time::HiRes;

my $AMIN_NS = 'http://projectamin.org/ns/2026/';

sub build_zcap_token (%o) {
    # Real e2e: ML-DSA-87 signature issued by the Rust toolchain (bctool) —
    # the same production signer — verifies against Amin::Auth::ZCap with
    # the VK registered as a mesh trust anchor.  Falls back to the legacy
    # structural placeholder when no signer binary is present.
    my %o = (
        tiers          => [qw(shared metal-32c metal-16c metal-96c)],
        zones          => [qw(us-east-1 us-west-2 global shared)],
        netpols        => [ map "vpc-$_", 'a'..'z' ],
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

sub profile_xml ($inner) {
    qq{<?xml version="1.0"?><amin:profile xmlns:amin="$AMIN_NS"><amin:zcap amin:token="$ZC_PERMISSIVE"/>$inner</amin:profile>}
}

# ── TR-10.1: Spawn → early result kind=running + pid; then Signal closes.
{
    my $xml = profile_xml(<<'TEN');
  <amin:spawn amin:id="job-slow-sleep" amin:name="sleeper">
    <amin:shell amin:dir="/tmp"/>
    <amin:argv>sleep</amin:argv>
    <amin:value>15</amin:value>
  </amin:spawn>
TEN

    # ── 10.1a: Short wait, then snapshot.  Run as Dispatcher->run inside
    # an alarm wrapper so we can interrupt it while sleep 15 is still
    # live.  (Since Spawn does not emit status on its own, the SAX
    # pipeline will run to completion once it reaches end_profile,
    # regardless of whether the child process is still live — there's
    # no finish harness call in Spawn path.  So Dispatcher completes
    # in <50ms.)
    my $writer_a = Amin::Handler::Writer->new(indent => 2);
    my $log_a    = Amin::Log::Standard->new(stderr => 0);
    my $out_a = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer_a,
        Log        => $log_a,
    );
    ok(length($out_a // '') > 100, '10.1a: spawn run produced non-empty SAX stream');

    like($out_a, qr{<amin:result\b[^>]*\bamin:kind="running"},
         '10.1a: spawn emits <result kind=running> immediately');
    my $pid;
    if ($out_a =~ m{<amin:stream\b[^>]*\bamin:channel="argv">[^<]*sleep\s+15}s) {
        pass('10.1a: argv stream contains "sleep 15" (captured build_argv output)');
    } else {
        fail('10.1a: argv stream captured');
    }

    # Spawn must NOT emit a <status> — that's Signal's exclusive job.
    unlike($out_a, qr{<amin:status\b},
           '10.1a: spawn NEVER emits <status> on its own — Signal owns it');

    # The child sleep 15 process must still be alive right now (we just
    # started it, sleep has ~14.9s remaining).
    my $reg = Amin::Command::Spawn->registry;
    ok(scalar keys(%$reg) >= 1, '10.1a: 1 entry in Amin::Command::Spawn registry after');
    my $job_ref = $reg->{'job-slow-sleep'};
    ok(defined($job_ref) && $job_ref->{pid} > 0,
       '10.1a: registry[job-slow-sleep] → live PID >0');
    $pid = $job_ref->{pid};

    # Verify OS-level process exists (read /proc/$pid/comm or kill 0).
    if (defined $pid && $pid > 0) {
        my $ok = kill 0, $pid;
        is($ok, 1, "10.1a: OS confirms pid=$pid is still running (no SIGCHLD yet)");
    } else {
        fail('10.1a: kill(0) check skipped — no pid in registry');
    }

    # ── 10.1b: Send SIGTERM via Amin::Command::Signal.
    my $xml_signal = profile_xml(<<'SIG');
  <amin:signal amin:target="job-slow-sleep" amin:signal="TERM"/>
SIG
    my $writer_b = Amin::Handler::Writer->new(indent => 2);
    my $log_b    = Amin::Log::Standard->new(stderr => 0);
    my $out_b = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml_signal,
        Handler    => $writer_b,
        Log        => $log_b,
    );

    # Signal emits its OWN <result><status> pair (the signal-command result,
    # which captures the reaped Spawn's final rc/signal).
    like($out_b, qr{<amin:result\b},       '10.1b: signal emits its own <result> wrapper');
    like($out_b, qr{<amin:status\b[^>]*\bamin:exit_kind="signal"},
         '10.1b: <status exit_kind=signal> after SIGTERM delivered + reaped');
    like($out_b, qr{<amin:status\b[^>]*\bamin:rc="-15"},
         '10.1b: <status rc=-15> (negative rc on signal avoids rc=0 ambiguity)');
    like($out_b, qr{<amin:status\b[^>]*\bamin:kind="error"},
         '10.1b: status kind=error after signal delivery');
    like($out_b, qr{<amin:status\b[^>]*\bamin:duration="[0-9]+\.[0-9]+"},
         '10.1b: duration present in status (spawn_created_at → POLLRDHUP proxy)');
    like($out_b, qr{<amin:status\b[^>]*\bamin:pid="$pid"},
         "10.1b: status pid=$pid matches spawn registry pid")
        if defined $pid;

    # Confirm Spawn registry cleared (no zombie registration entries).
    is(scalar keys(%{Amin::Command::Spawn->registry}), 0,
       '10.1b: Spawn registry empty after Signal reap + unregister');
    is(scalar keys(%{Amin::Command::Spawn->by_pid}),   0,
       '10.1b: Spawn by_pid index also empty');

    # OS-level: pid MUST no longer exist (no zombie leak either — waitpid done).
    if (defined $pid && $pid > 0) {
        my $exists = kill 0, $pid;
        ok(!$exists, "10.1b: OS confirms pid=$pid fully reaped (not even zombie)");
    }
}

# ── TR-10.2: Result ↔ Status pair parity.
{
    my $xml = profile_xml(<<'TWO');
  <amin:command name="echo">
    <amin:param name="text">first</amin:param>
  </amin:command>
  <amin:command name="echo">
    <amin:param name="text">second</amin:param>
  </amin:command>
  <amin:command name="echo">
    <amin:param name="text">third</amin:param>
  </amin:command>
  <amin:spawn amin:id="s1" amin:name="bg1">
    <amin:argv>sleep</amin:argv><amin:value>10</amin:value>
  </amin:spawn>
  <amin:spawn amin:id="s2" amin:name="bg2">
    <amin:argv>sleep</amin:argv><amin:value>10</amin:value>
  </amin:spawn>
  <amin:signal amin:target="s1" amin:signal="TERM"/>
  <amin:signal amin:target="s2" amin:signal="TERM"/>
TWO

    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $log    = Amin::Log::Standard->new(stderr => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => $log,
    );

    my $n_result = () = $out =~ /<amin:result\b/g;
    my $n_status = () = $out =~ /<amin:status\b/g;
    is($n_result, 7, '10.2: 7 <result> nodes total (3 echo + 2 spawn + 2 signal)');
    is($n_status, 5, '10.2: 5 <status> nodes total (3 echo self-status + 2 signal reaper-status)');

    # Pair parity II (DOM, lifecycle-aware):
    #   Results are classified by HOW MANY direct status children they have
    #   (NOT by result/@kind, because Exec opens result with kind=running then
    #    cannot retroactively edit SAX output — the terminal kind lives on the
    #    <status> child element).
    #   - Live spawn results → exactly 0 direct <status> children.  (Spawn
    #     never self-terminates its SAX result; Signal emits the reaped
    #     spawn's terminal status inside the Signal's own result wrapper.)
    #   - Closed results (Exec self-close + Signal reaper wrapper) → exactly
    #     1 direct <status> child.
    #   - Total: 2*0 + 5*1 = 5 statuses (matches regex count above).
    require XML::LibXML;
    my $dom = XML::LibXML->load_xml(string => $out);
    my @results = $dom->getElementsByLocalName('result');
    is(scalar @results, 7, '10.2 DOM: 7 result nodes');
    my ($n_live_zero, $n_closed_one) = (0, 0);
    my $bad = 0;
    for my $r (@results) {
        my @direct_status =
            grep { $_->localName && $_->localName eq 'status' }
            grep { $_->nodeType == 1 }
            $r->childNodes;
        if    (@direct_status == 0) { $n_live_zero++ }
        elsif (@direct_status == 1) { $n_closed_one++ }
        else { $bad++; diag "result has " . 0+@direct_status . " direct status children (expected 0 or 1)" }
    }
    is($n_live_zero, 2, '10.2 DOM: exactly 2 spawn results have 0 direct status children (live processes; signal owns terminal status in signal wrapper)');
    is($n_closed_one, 5, '10.2 DOM: exactly 5 closed results (3 echo + 2 signal) have exactly 1 direct status child each');
    is($bad, 0, '10.2 DOM: no violations of lifecycle-aware pair-parity invariant (every result has either 0 or 1 status children)');

    # No streams leak AFTER a status inside a result (status is the
    # terminal data-plane child of result — no more line emission past
    # final status). Additive siblings (billing, seal) are permitted.
    my $leak = 0;
    for my $r (@results) {
        my @kids = grep { $_->nodeType == 1 } $r->childNodes;
        my $saw_status = 0;
        for my $k (@kids) {
            my $ln = $k->localName // '';
            if ($saw_status && $ln eq 'stream') {
                $leak++;
                diag "leak: <stream> appears AFTER <status> inside same <result>";
            }
            $saw_status = 1 if $ln eq 'status';
        }
    }
    is($leak, 0, '10.2 DOM: <status> is terminal data-plane child of <result>; no <stream> leaks after it (additive billing/seal siblings permitted)');
}

# ── Bonus: Dryrun for Spawn and Signal behave correctly without IPC.
{
    my $xml = profile_xml(<<'DRY');
  <amin:spawn amin:id="dry1" amin:name="drysleeper">
    <amin:argv>sleep</amin:argv><amin:value>999</amin:value>
  </amin:spawn>
  <amin:signal amin:target="dry1" amin:signal="KILL"/>
DRY
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $log    = Amin::Log::Standard->new(stderr => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'dryrun',
        source_xml => $xml,
        Handler    => $writer,
        Log        => $log,
    );
    my @r = ($out =~ /<amin:result[^>]*amin:kind="dryrun"/g);
    is(scalar @r, 2, 'bonus: spawn+signal in dryrun → 2× kind=dryrun result');
    is($log->error_count, 0, 'bonus: dryrun produces 0 log errors');
    is(scalar keys(%{Amin::Command::Spawn->registry}), 0,
       'bonus: dryrun produces NO registry entries (sanity guard)');
}

done_testing();
