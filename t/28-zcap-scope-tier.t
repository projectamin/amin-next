use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
require MIME::Base64;

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(metal-32c metal-16c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 us-west-2);
    my @netps  = $o{netpols}? @{$o{netpols}}: qw(vpc-a vpc-b);
    my $max_r  = $o{max_redundancy} // 3;
    my $vpc_q  = $o{vpc_quota} // 4;
    my $mem_t  = $o{memory_tier} // 1;
    my $tenant = $o{tenant_id} // 't-tenant-0123456789abc';
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
    my $bytes = '';
    $bytes .= $sig;
    $bytes .= $vk;
    $bytes .= $scope_hash;
    $bytes .= pack('Q<', $ts);
    $bytes .= pack('v',  scalar @tiers);
    $bytes .= pack('v',  scalar @zones);
    $bytes .= pack('v',  scalar @netps);
    $bytes .= pack('C',  $max_r);
    $bytes .= pack('V',  $vpc_q);
    $bytes .= pack('C',  $mem_t);
    $bytes .= pack('v',  length($tenant)) . $tenant;
    $bytes .= $tier_data;
    $bytes .= $zone_data;
    $bytes .= $netp_data;
    return MIME::Base64::encode_base64($bytes, '');
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
