#!/usr/bin/env perl
# t/44-ucc.t — Uniform Commercial Code as Amin filter constructs.
#
# Verifies the article-to-filter mapping:
#   Art.1 General        -> Amin::UCC::General      (begin)  transaction form
#   Art.5 Letters of Cr. -> Amin::UCC::Credit       (begin)  LC authorization
#   Art.2 Sales          -> Amin::UCC::Sales        (middle) offer/acceptance
#   Art.3 Instruments    -> Amin::UCC::Instruments  (middle) signature verify
#   Art.4A Funds Transfer-> Amin::UCC::Settlement   (end)    settlement sibling
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;

my $AMIN_NS = 'http://projectamin.org/ns/2026/';
my $UCC_NS  = 'http://projectamin.org/ns/ucc/1';

sub build_zcap_token (%o) {
    my @tiers  = $o{tiers}  ? @{$o{tiers}}  : qw(shared metal-32c metal-16c metal-96c);
    my @zones  = $o{zones}  ? @{$o{zones}}  : qw(us-east-1 us-west-2 global shared);
    my @netps  = $o{netpols}? @{$o{netpols}}: (map "vpc-$_", 'a'..'z');
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

my $ZC = build_zcap_token();

sub run_ucc ($inner) {
    my $xml = qq{<?xml version="1.0"?>}
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:ucc="$UCC_NS">}
        . qq{<amin:zcap amin:token="$ZC"/>}
        . $inner
        . qq{</amin:profile>};
    return Amin::Machine::Dispatcher->run(
        source_xml => $xml,
        Handler    => Amin::Handler::Writer->new(indent => 0),
        Log        => Amin::Log::Standard->new(stderr => 0),
        mode       => 'render',
    );
}

# ── TR-UCC.1: Full happy-path commercial transaction ───────────────────
{
    my $out = run_ucc(<<'TEN');
  <ucc:transaction ucc:governing-law="UCC">
    <ucc:party>seller-co</ucc:party>
    <ucc:party>buyer-co</ucc:party>
    <ucc:subject>widget-lot-42</ucc:subject>
    <ucc:lc ucc:beneficiary="seller-co" ucc:expiry="2026-12-31"
            ucc:documents="sale,instrument">
      <ucc:sale>
        <ucc:goods>widget-42</ucc:goods>
        <ucc:price>1500.00</ucc:price>
        <ucc:delivery>shipment</ucc:delivery>
        <ucc:warranty>merchantability</ucc:warranty>
      </ucc:sale>
      <ucc:instrument ucc:kind="draft" ucc:maker="buyer-co"
                      ucc:payee="seller-co" ucc:amount="1500.00"/>
    </ucc:lc>
  </ucc:transaction>
TEN

    like($out, qr/ucc:kind="transaction-formed"/,
        'Art.1: transaction-formed event emitted for valid transaction');
    like($out, qr/ucc:governing_law="UCC"/,
        'Art.1: governing-law recorded');
    like($out, qr/ucc:parties="2"/,
        'Art.1: party count recorded');
    like($out, qr/ucc:kind="lc-opened"/,
        'Art.5: lc-opened event emitted');
    like($out, qr/ucc:kind="contract-formed"/,
        'Art.2: contract-formed event emitted');
    like($out, qr/ucc:kind="risk-of-loss-passed"/,
        'Art.2: risk-of-loss-passed event emitted');
    like($out, qr/<ucc:result[^>]*ucc:kind="accepted"/,
        'Art.2: sale result kind=accepted');
    like($out, qr/<ucc:settlement[^>]*ucc:amount="1500\.00"/,
        'Art.4A: settlement sibling emitted with instrument amount');
}

# ── TR-UCC.2: Art.1 form validation fail-closed ────────────────────────
{
    my $out = run_ucc(<<'TEN');
  <ucc:transaction ucc:governing-law="UCC">
    <ucc:party>sole-party</ucc:party>
  </ucc:transaction>
TEN

    like($out, qr/<ucc:result[^>]*ucc:kind="error"/,
        'Art.1: malformed transaction (one party) -> result kind=error');
    like($out, qr/ucc:rc="-4096"/,
        'Art.1: malformed transaction carries rc=-4096 (UCC_FORM_MALFORMED)');
    unlike($out, qr/ucc:kind="transaction-formed"/,
        'Art.1: no transaction-formed event on malformed input');
}

# ── TR-UCC.3: Art.5 LC discrepancy on non-conforming presentation ──────
{
    my $out = run_ucc(<<'TEN');
  <ucc:transaction ucc:governing-law="UCC">
    <ucc:party>a</ucc:party>
    <ucc:party>b</ucc:party>
    <ucc:subject>x</ucc:subject>
    <ucc:lc ucc:beneficiary="a" ucc:expiry="2026-12-31"
            ucc:documents="sale">
      <ucc:instrument ucc:kind="note" ucc:maker="a" ucc:payee="b" ucc:amount="10"/>
    </ucc:lc>
  </ucc:transaction>
TEN

    like($out, qr/ucc:kind="lc-discrepancy"/,
        'Art.5: non-conforming document (instrument not in allowlist) -> lc-discrepancy');
    like($out, qr/ucc:document="instrument"/,
        'Art.5: discrepancy names the non-conforming document');
}

# ── TR-UCC.4: Art.2 closed-world term validation ───────────────────────
{
    my $out = run_ucc(<<'TEN');
  <ucc:transaction ucc:governing-law="UCC">
    <ucc:party>a</ucc:party>
    <ucc:party>b</ucc:party>
    <ucc:subject>x</ucc:subject>
    <ucc:sale>
      <ucc:goods>g</ucc:goods>
      <ucc:price>1</ucc:price>
      <ucc:warranty>magic-guarantee</ucc:warranty>
    </ucc:sale>
  </ucc:transaction>
TEN

    like($out, qr/<ucc:result[^>]*ucc:kind="error"/,
        'Art.2: unrecognized warranty term -> result kind=error');
    like($out, qr/ucc:exit_kind="ucc_sale_term"/,
        'Art.2: error exit_kind=ucc_sale_term');
    unlike($out, qr/ucc:kind="contract-formed"/,
        'Art.2: no contract-formed on invalid term');
}

# ── TR-UCC.5: Art.3 instrument signature path (no-crypto structural check)
{
    my $out = run_ucc(<<'TEN');
  <ucc:transaction ucc:governing-law="UCC">
    <ucc:party>a</ucc:party>
    <ucc:party>b</ucc:party>
    <ucc:subject>x</ucc:subject>
    <ucc:instrument ucc:kind="check" ucc:maker="a" ucc:payee="b" ucc:amount="42.50"/>
  </ucc:transaction>
TEN

    like($out, qr/ucc:kind="signature-verified"/,
        'Art.3: structural instrument accepted, signature-verified event emitted');
    like($out, qr/ucc:alg="ML-DSA-87"/,
        'Art.3: signature-verified event records ML-DSA-87 algorithm');
}

done_testing;
