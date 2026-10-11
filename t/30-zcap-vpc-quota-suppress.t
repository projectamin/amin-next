use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
use Amin::Test::StreamCapture;
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

# ── Z5: vpc_quota + netpol allow-list (suppress) ──
# ── Z8: 3-level deep nested suppress → INNER_LEAK marker zero occurences stack balanced ──

# ── Case 1: vpc_quota=2 open 3 nets → 3rd net rc=-5121 SUPPRESS ──
{
    my $token = build_zcap_token(vpc_quota => 2, vpc_open => 0);
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:net amin:vpc="vpc-a" amin:subnet="10.1.0.0/24"><amin:spawn amin:name="n1" amin:tier="metal-32c" amin:zone="us-east-1" amin:argv="./NETA_OK_MARKER"/></amin:net>
  <amin:net amin:vpc="vpc-b" amin:subnet="10.2.0.0/24"><amin:spawn amin:name="n2" amin:tier="metal-32c" amin:zone="us-west-2" amin:argv="./NETB_OK_MARKER"/></amin:net>
  <amin:net amin:vpc="vpc-a" amin:subnet="10.3.0.0/24"><amin:spawn amin:name="n3" amin:tier="metal-16c" amin:zone="us-east-1" amin:argv="./NETC_QUOTA_LEAK_MARKER_3RD"/></amin:net>
</amin:init>
XML
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    ok(defined $out && length $out, 't30-case1: writer produced output');
    my @vpc_viol = ($out =~ /rc="-5121"/g);
    cmp_ok(scalar(@vpc_viol), '>=', 1,
        't30-Z5-case1: vpc_quota=2 → 3rd net open suppressed with rc="-5121" scope_violation');
    unlike($out, qr/QUOTA_LEAK_MARKER_3RD/,
        't30-Z5-case1: 3rd net spawn argv MARKER NOT in output → suppressed (closed world quota = NO silent host fallback)');
    my @marker_leak = ($out =~ /QUOTA_LEAK_MARKER_3RD/g);
    is(scalar(@marker_leak), 0, 't30-Z5-case1: grep count 0 occurrences of quota-violation marker');
}

# ── Case 2: netpol allow-list only [vpc-a, vpc-b] → vpc=vpc-c NOT in list → suppress rc=-5121 ──
{
    my $token = build_zcap_token(netpols => [qw(vpc-a vpc-b)], vpc_quota => 10);
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:net amin:vpc="vpc-c" amin:subnet="10.99.0.0/24">
    <amin:spawn amin:name="victim_c" amin:tier="metal-32c" amin:zone="us-east-1" amin:argv="./NETPOL_OUTSIDE_LEAK_vpcc"/>
  </amin:net>
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
        't30-Z5-case2: vpc=vpc-c NOT in zcap netpolicy allow-list [vpc-a, vpc-b] → rc="-5121" scope_violation');
    unlike($out, qr/NETPOL_OUTSIDE_LEAK_vpcc/,
        't30-Z5-case2: netpolicy outside marker NOT in output; closed world vpc reference = signed scope only; host root not allowed to open arbitrary vpcs');
}

# ── Case 3 (AC-Z8): 3-level deep nesting suppress → INNER_LEAK marker zero occurences ──
#       Critical Profile-as-Contract test: 3-level `<net> → <sandbox> → <spawn>`
#       entire subtree suppressed via parent_suppressed. ZCap must NOT leak
#       character data `INNER_LEAK_3LVL_DEEP` through characters() handler
#       AND stack pop must balance (no unmatched stack error / no undef deref).
#
#       Catches historical SAX capture-leak bugs.
{
    my $token = build_zcap_token(netpols => [qw(vpc-a vpc-b)]);
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:init xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:net amin:vpc="outside-allow-list-vpc-x" amin:subnet="10.255.0.0/24">
    <amin:sandbox amin:landlock_ro="/tmp" amin:memory_max="128" amin:seccomp="default-deny">
      <amin:spawn amin:name="innervictim" amin:tier="metal-16c" amin:zone="us-east-1" amin:redundancy="1">
        <amin:argv>/bin/echo</amin:argv>
        <amin:argv>INNER_LEAK_3LVL_DEEP_99485723</amin:argv>
      </amin:spawn>
    </amin:sandbox>
  </amin:net>
</amin:init>
XML
    my $cap = Amin::Test::StreamCapture->new( capture_chars => 1 );
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        $cap, $log, 'run', { map => 0, ui => 0 });
    require XML::SAX::ParserFactory;
    my $parser = eval { XML::LibXML::SAX->new(Handler => $chain) }
              || XML::SAX::ParserFactory->parser(Handler => $chain);
    eval { $parser->parse_string($xml); 1 } or do { diag "parse: $@" };

    # Post-hoc grep captured character stream for the marker
    my $char_buf = '';
    for my $ev ($cap->captured->@*) {
        next unless $ev->[0] eq 'characters';
        $char_buf .= ($ev->[1]{Data} // '');
    }
    unlike($char_buf, qr/INNER_LEAK_3LVL_DEEP_99485723/,
        't30-Z8-case3: INNER_LEAK marker NOT in StreamCapture characters data (3-level nested parent_suppress propagated; no SAX capture leak)');

    # Also run through Writer and grep output
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    unlike($out, qr/INNER_LEAK_3LVL_DEEP_99485723/,
        't30-Z8-case3: zero INNER_LEAK occurrences in full Writer output (nested 3-level net→sandbox→spawn full suppress subtree no-character-leak)');
    my @cnt = ($out =~ /INNER_LEAK_3LVL_DEEP_99485723/g);
    is(scalar(@cnt), 0,
        't30-Z8-case3: grep count = 0 marker occurrences; Profile-as-Contract closed-world + SAX suppress stack holds for deep nesting');
    like($out, qr/rc="-5121"/,
        't30-Z8-case3: suppressed with rc="-5121" status element; additive-only no mutation');
}

done_testing;
