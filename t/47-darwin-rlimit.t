#!/usr/bin/env perl
# t/47-darwin-rlimit.t — Phase 1 darwin backend (docs/darwin-sandbox-plan.md):
#   * pids_max            honored via RLIMIT_NPROC (survives exec, child proves it)
#   * memory_max          FAIL CLOSED — verified unenforceable on darwin
#                         (RLIMIT_AS/RLIMIT_DATA dropped across exec, undocumented
#                         EINVAL floor; see darwin.rs module header + plan doc)
#   * landlock-class      FAIL CLOSED (Seatbelt Phase 2 pending)
# The assertions below were derived from direct kernel probes on this host
# (macOS arm64, darwin 27.2.0) — not from assumption.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;
require Amin::Command::Spawn;

my $AMIN_NS = 'http://projectamin.org/ns/2026/';

sub build_zcap_token (%o) {
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

sub run_dispatch ($xml) {
    my $writer = Amin::Handler::Writer->new(indent => 2);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    return defined $out ? $out : '';
}

Amin::Command::Spawn->registry->%* = ();

# ── Case 1: pids_max-only scope is HONORED on darwin ────────────────────
# The child shell reports `ulimit -u` (= RLIMIT_NPROC); the number must equal
# the declared pids_max. This proves the manifest → darwin backend → exec
# chain delivers the declared workload contract to the exec'd image.
if ($^O eq 'darwin') {
    my $xml = profile_xml(<<'XML');
  <amin:sandbox xmlns:amin="http://projectamin.org/ns/2026/"
      amin:pids_max="512">
    <amin:exec amin:name="nproc_report">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>ulimit -u</amin:argv>
    </amin:exec>
  </amin:sandbox>
XML
    my $out = run_dispatch($xml);
    like($out, qr/rc="0"/,
         'Case 1 darwin: pids_max-only scope honors RLIMIT_NPROC → exec rc=0');
    like($out, qr/amin:exit_kind="(?:ok|success)"/,
         'Case 1 darwin: terminal ok status for the workload');
    unlike($out, qr/sandbox_missing_abi/,
           'Case 1 darwin: NO missing-abi failure for pids-only scope');
    my ($num) = $out =~ /<amin:stream amin:channel="out">\s*(\d+)/;
    is($num, '512',
       'Case 1 darwin: child `ulimit -u` reports the DECLARED pids_max (512) — limit reached the exec image');
}

Amin::Command::Spawn->registry->%* = ();

# ── Case 2: memory_max-only scope FAILS CLOSED on darwin ────────────────
# Direct kernel probes prove RLIMIT_AS/RLIMIT_DATA drop across exec and have
# no documented floor — honoring this scope would be silent degradation.
# The declared contract is therefore unenforceable → -4097, never executed.
if ($^O eq 'darwin') {
    my $xml = profile_xml(<<'XML');
  <amin:sandbox xmlns:amin="http://projectamin.org/ns/2026/"
      amin:memory_max="1048576">
    <amin:exec amin:name="oom_alloc">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo SURVIVED</amin:argv>
    </amin:exec>
  </amin:sandbox>
XML
    my $out = run_dispatch($xml);
    like($out, qr/rc="-4097"/,
         'Case 2 darwin: memory contract unenforceable → fail-closed -4097 (NFR-SB-4)');
    unlike($out, qr{<amin:stream amin:channel="out">\s*SURVIVED},
           'Case 2 darwin: workload NEVER ran (no SURVIVED on out channel)');
    unlike($out, qr/amin:exit_kind="(?:ok|success)"/,
           'Case 2 darwin: no terminal ok for the unenforceable memory contract');
}

Amin::Command::Spawn->registry->%* = ();

# ── Case 3: landlock-class scope FAILS CLOSED on darwin ─────────────────
# Seatbelt is Phase 2 (docs/darwin-sandbox-plan.md). Until then, a scope
# declaring filesystem confinement MUST NOT degrade silently.
if ($^O eq 'darwin') {
    my $xml = profile_xml(<<'XML');
  <amin:sandbox xmlns:amin="http://projectamin.org/ns/2026/"
      amin:landlock_ro="/usr:/bin">
    <amin:exec amin:name="fs_only">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo CONFINED</amin:argv>
    </amin:exec>
  </amin:sandbox>
XML
    my $out = run_dispatch($xml);
    like($out, qr/rc="-4097"/,
         'Case 3 darwin: landlock-class scope → fail-closed -4097 (Seatbelt Phase 2 pending)');
    unlike($out, qr{<amin:stream amin:channel="out">\s*CONFINED},
           'Case 3 darwin: workload NEVER ran (no CONFINED on out channel)');
    unlike($out, qr/amin:exit_kind="(?:ok|success)"/,
           'Case 3 darwin: no terminal ok for unenforceable fs contract');
}

# ── Case 4 (non-darwin cross-checks, keep the suite honest everywhere) ──
if ($^O eq 'linux') {
    my $xml = profile_xml(<<'XML');
  <amin:sandbox xmlns:amin="http://projectamin.org/ns/2026/"
      amin:memory_max="1073741824">
    <amin:exec amin:name="mem_ok">
      <amin:argv>/bin/sh</amin:argv>
      <amin:argv>-c</amin:argv>
      <amin:argv>echo LINUX_CGROUP_OK</amin:argv>
    </amin:exec>
  </amin:sandbox>
XML
    my $out = run_dispatch($xml);
    unlike($out, qr/sandbox_missing_abi/,
           'Case 4 linux: cgroup v2 honors memory.max, no missing-abi');
    like($out, qr/amin:exit_kind="(?:ok|success)"/,
         'Case 4 linux: clean terminal status for 1GiB memory scope');
}

Amin::Command::Spawn->registry->%* = ();

done_testing;
