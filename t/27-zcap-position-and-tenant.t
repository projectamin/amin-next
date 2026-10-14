use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Log::Standard;
use Amin::Handler::Writer;
use Amin::Machine::Dispatcher;
use Amin::Test::StreamCapture;
require MIME::Base64;

# ── Shared token builder (Case B structural — works with/without Crypt::ML-DSA) ──
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

# Helper to extract attr values (Clark-key tolerant)
sub attr_val ($el, $want) {
    my $A = $el->{Attributes} // {};
    for my $k (keys %$A) {
        next unless ref $A->{$k} eq 'HASH';
        my $ln = $A->{$k}{LocalName} // '';
        if ($ln eq '') { (my $kk = $k) =~ s/^\{[^}]*\}//; $ln = $kk; }
        next unless $ln eq $want;
        return $A->{$k}{Value} if defined $A->{$k}{Value} && length $A->{$k}{Value};
    }
    return undef;
}

# ── Z1: Dispatcher begin[] count + idx0 = ZCap ──
{
    require Amin::Machine::MachineSpec;
    my $spec = Amin::Machine::MachineSpec->new->spec;
    my @begin = grep { ($_->{meta}{position} // 'middle') eq 'begin' } $spec->{filters}->@*;
    is(scalar(@begin), 7, 't27-Z1: spec begin[] count = 7 (ZCap/Cond/Validator/UCC::General/UCC::Credit/AI::Gate/Placement)');
    is($begin[0]{class}, 'Amin::Auth::ZCap',
        't27-Z1: spec begin idx 0 = Auth::ZCap (outermost auth boundary)');
}

# ── Z2: Valid token → synthetic <tenant> FIRST child + Z7 add-only no mutation ──
{
    my $token = build_zcap_token();
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:root xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:stage amin:id="s01" amin:name="supervisor">
    <amin:exec amin:name="prober" amin:tier="metal-32c" amin:zone="us-east-1" amin:redundancy="2">
      <amin:argv>/bin/echo</amin:argv><amin:argv>POS_TENANT_OK</amin:argv>
    </amin:exec>
  </amin:stage>
</amin:root>
XML

    # StreamCapture: record event order for Z2 + Z7 assertions
    my $cap = Amin::Test::StreamCapture->new( capture_chars => 0 );
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        $cap, $log, 'run', { map => 0, ui => 0 });
    require XML::SAX::ParserFactory;
    my $parser = eval { XML::LibXML::SAX->new(Handler => $chain) }
              || XML::SAX::ParserFactory->parser(Handler => $chain);
    eval { $parser->parse_string($xml); 1 } or do { diag "parse: $@" };

    my @captured = $cap->captured->@*;
    my @starts = map { $_->[1] } grep { $_->[0] eq 'start_element' } @captured;

    # Find first amin:tenant (synthetic) vs first amin:stage (real) vs amin:exec position
    my ($tenant_idx, $stage_idx, $exec_idx);
    for my $i (0..$#starts) {
        my $ns = $starts[$i]{NamespaceURI} // '';
        my $ln = $starts[$i]{LocalName} // '';
        if (($ns eq Amin::NS() || $ns eq '') && $ln eq 'tenant') {
            $tenant_idx //= $i; next;
        }
        if (($ns eq Amin::NS() || $ns eq '') && $ln eq 'stage') {
            $stage_idx //= $i; next;
        }
        if (($ns eq Amin::NS() || $ns eq '') && $ln eq 'exec') {
            $exec_idx //= $i; next;
        }
    }
    ok(defined $tenant_idx, 't27-Z2: synthetic tenant present in captured stream');
    ok(defined $stage_idx,  't27-Z2: real stage element captured');
    ok(defined $exec_idx,   't27-Z2: real exec element captured through chain');

    cmp_ok($tenant_idx, '<', $stage_idx,
        't27-Z2: synthetic <tenant> additive delta BEFORE first real <stage> (SAX additive contract per user rule #1)');
    cmp_ok($stage_idx, '<', $exec_idx,
        't27-Z2: event order preserved (stage then exec)');

    # Check tenant attrs have values from token build
    my $tenant_el = (grep {
        my $n = $_->{NamespaceURI} // ''; my $l = $_->{LocalName} // '';
        ($n eq Amin::NS() || $n eq '') && $l eq 'tenant'
    } @starts)[0];
    ok(defined $tenant_el, 't27-Z2: first tenant element located');
    like(attr_val($tenant_el, 'id') // '', qr/^zcap:/,
        't27-Z2: synthetic tenant id prefixed zcap:<12chars> (correct form)');
    is(attr_val($tenant_el, 'tenant_id'), 't-tenant-0123456789abc',
        't27-Z2: synthetic tenant_id attr = token tenant field');
    is(attr_val($tenant_el, 'vpc_quota'), 4,
        't27-Z2: synthetic vpc_quota attr matches token');
    like(attr_val($tenant_el, 'tiers') // '', qr/metal-16c/,
        't27-Z2: tiers contains allow-list metal-16c');
    like(attr_val($tenant_el, 'zones') // '', qr/us-east-1/,
        't27-Z2: zones contains allow-list us-east-1');

    # ── Z7: Additive-only NO mutation → spawn attrs SHA256 unchanged through chain ──
    # Locate the exec element in the captured stream, compare attrs against
    # the source XML attr values byte-for-byte.
    my $exec_el = (grep {
        my $n = $_->{NamespaceURI} // ''; my $l = $_->{LocalName} // '';
        ($n eq Amin::NS() || $n eq '') && $l eq 'exec'
    } @starts)[0];
    ok(defined $exec_el, 't27-Z7: exec element captured through full chain');
    is(attr_val($exec_el, 'name'), 'prober',
        't27-Z7: exec name attr unchanged (SAX add-only rule — no inline edits to existing attrs)');
    is(attr_val($exec_el, 'tier'), 'metal-32c',
        't27-Z7: exec tier attr byte-identical to source (ZCap did NOT modify existing spawn attrs — only injected sibling tenant)');
    is(attr_val($exec_el, 'redundancy'), '2',
        't27-Z7: exec redundancy attr unchanged; AC-Z7 add-only DI-1 delta contract');
    ok(!defined attr_val($exec_el, 'tenant_id'),
        't27-Z7: exec does NOT carry tenant_id attr (ZCap injects NEW sibling; never mutates in-transit elements)');
}

# ── Run with Writer to check end-to-end output sanity ──
{
    my $token = build_zcap_token();
    my $xml = sprintf(<<'XML', $token);
<?xml version="1.0"?>
<amin:root xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:zcap amin:token="%s"/>
  <amin:stage amin:id="s01" amin:name="workload-ready">
    <amin:spawn amin:name="m1" amin:tier="metal-16c" amin:zone="us-west-2" amin:redundancy="1" amin:argv="./M1_OK_MARKER">
    </amin:spawn>
  </amin:stage>
</amin:root>
XML
    my $writer = Amin::Handler::Writer->new(indent => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'run',
        source_xml => $xml,
        Handler    => $writer,
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
    ok(defined $out && length $out, 't27-E2E: writer produced output on valid zcap');
    like($out, qr/<(?:amin:)?tenant\b[^>]*\bid=/s,
        't27-E2E: tenant synthetic delta present in writer output');
    my @tenant_tags = ($out =~ /<(?:amin:)?tenant\b[^>]*>/g);
    is(scalar(@tenant_tags), 1,
        't27-E2E: exactly 1 tenant synthetic injected (no duplicates)');
}

done_testing;
