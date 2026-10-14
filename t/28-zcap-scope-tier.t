use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
require MIME::Base64;

sub build_zcap_token (%o) {
    # Real e2e: ML-DSA-87 signature issued by the Rust toolchain (bctool) —
    # the same production signer — verifies against Amin::Auth::ZCap with
    # the VK registered as a mesh trust anchor.  Falls back to the legacy
    # structural placeholder when no signer binary is present.
    my %o = (
        tiers          => [qw(metal-32c metal-16c)],
        zones          => [qw(us-east-1 us-west-2)],
        netpols        => [qw(vpc-a vpc-b)],
        max_redundancy => 3,
        vpc_quota      => 4,
        memory_tier    => 1,
        tenant_id      => 't-tenant-0123456789abc',
        ts             => 1735689600,
        @_,
    );
    require Amin::Test::ZCapSign;
    return Amin::Test::ZCapSign::make_zcap_token(%o);
}

# ── Z3: Tier/redundancy/memory violation → rc=-5121 scope_violation drop ──

# ── Case 1: tier=metal-96c NOT in allow-list [metal-32c, metal-16c] → SUPPRESS ──
{
    my $token = build_zcap_token();
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:exec amin:name="bad_tier" amin:tier="metal-96c" amin:zone="us-east-1" amin:redundancy="1">
    <amin:argv>/bin/sh</amin:argv><amin:argv>-c</amin:argv><amin:argv>echo TIER96C_LEAK_MARKER_XYZ</amin:argv>
  </amin:exec>
</amin:init>
XML
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    ok(defined $out && length $out, 't28-case1: writer produced output');
    like($out, qr/rc="-5121"/,
        't28-Z3-case1: tier metal-96c OUTSIDE zcap allow-list → rc="-5121" scope_violation fail-closed');
    like($out, qr/exit_kind="zcap"/,
        't28-Z3-case1: exit_kind=zcap present on status element');
    unlike($out, qr/TIER96C_LEAK_MARKER_XYZ/,
        't28-Z3-case1: NO workload marker leak INNER payload; ZCap suppress before middle Exec sees start_element');
    my @bad = ($out =~ /TIER96C_LEAK_MARKER_XYZ/g);
    is(scalar(@bad), 0,
        't28-Z3-case1: 0 occurrences of TIER96C_LEAK_MARKER_XYZ in entire Writer output; 0 shell expansion 0 executed argv bytes');
}

# ── Case 2: redundancy=4 > max_redundancy=3 → SUPPRESS ──
{
    my $token = build_zcap_token(max_redundancy => 3);
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:spawn amin:name="over_redundant" amin:tier="metal-32c" amin:zone="us-west-2" amin:redundancy="4" amin:argv="./REDUNDANCY_LEAK_MARKER_4x" />
</amin:init>
XML
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    like($out, qr/rc="-5121"/,
        't28-Z3-case2: redundancy=4 > zcap max_redundancy=3 → rc="-5121" scope_violation');
    unlike($out, qr/REDUNDANCY_LEAK_MARKER_4x/,
        't28-Z3-case2: NO redundancy violation workload marker through SAX suppressed subtree');
}

# ── Case 3: sandbox memory_max=2048M > memory_tier=0 ceiling=256M → SUPPRESS ──
{
    my $token = build_zcap_token(memory_tier => 0); # memory tier ceiling 0 = 256M
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:sandbox amin:memory_max="2048" amin:landlock_ro="/data">
    <amin:exec amin:name="memhog" amin:tier="metal-16c" amin:zone="us-east-1" amin:redundancy="1">
      <amin:argv>/usr/bin/memhog</amin:argv><amin:argv>MEMORY_LEAK_MARKER_2GB</amin:argv>
    </amin:exec>
  </amin:sandbox>
</amin:init>
XML
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    like($out, qr/rc="-5121"/,
        't28-Z3-case3: sandbox memory_max 2048M > memory_tier 0 ceiling 256M → rc="-5121"');
    unlike($out, qr/MEMORY_LEAK_MARKER_2GB/,
        't28-Z3-case3: memhog binary path argv marker NOT in output; SAX subtree full suppress 0 shell/exec bytes pass through');
}

# ── Case 4: positive control tier=metal-32c PASS → no rc=-5121; marker payload ALLOWED ──
{
    my $token = build_zcap_token();
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:exec amin:name="ok_tier" amin:tier="metal-32c" amin:zone="us-east-1" amin:redundancy="2">
    <amin:argv>/bin/echo</amin:argv><amin:argv>POSITIVE_OK_MARKER_M32</amin:argv>
  </amin:exec>
</amin:init>
XML
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    unlike($out, qr/rc="-5121"/,
        't28-Z3-case4 positive: tier=metal-32c metal-16c in set PASS no scope violation rc');
    like($out, qr/POSITIVE_OK_MARKER_M32/,
        't28-Z3-case4 positive: allowed tier+zone+redundancy passes through chain → marker present in output (closed world valid scope executes)');
}

done_testing;
