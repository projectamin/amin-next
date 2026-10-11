#!/usr/bin/env perl
# Task 1 TR-1.3 — NS_BITCACHE=4 + new NAME_IDs (bc:* / ainit / exec-net) +
#                 NS_ESCAPE custom-namespace elements survive BSAX roundtrip.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

BEGIN {
    my @need = qw(Amin::Handler::Writer  Amin::Handler::BSAX
                  Amin::Generator::BSAX  XML::LibXML::SAX
                  Amin::Test::RecordingHandler);
    for my $mod (@need) {
        eval "require $mod; $mod->import; 1"
            or skip_all("Missing required dependency: $mod  — $@");
    }
}

# Amin::Test::RecordingHandler is the shared replacement for the duplicated
# inline RecordingHandler class that used to live in both t/11 and t/12.
# API: $r->captured returns filter-local arrayref of captured events; no
# more manual `@RecordingHandler::Captured = ()` reset hacks between runs.

my $NS_AMIN = 'http://projectamin.org/ns/2026/';
my $NS_BC      = 'http://projectamin.org/ns/bc/';
my $NS_SOX     = 'https://corp.example.test/ns/sox/v1';  # NS_ESCAPE path

sub _ns_of_prefix ($p) {
    return $NS_AMIN if $p eq 'amin';
    return $NS_BC   if $p eq 'bc';
    return $NS_SOX  if $p eq 'sox';
    return '';
}

sub _el ($ns,$pfx,$ln,%a) {
    my $attrs = {};
    while (my ($k,$v) = each %a) {
        my ($p,$an) = ($k =~ /^([a-z]+):(.+)$/) ? ($1,$2) : ($pfx,$k);
        my $ns_uri = _ns_of_prefix($p);
        my $qname = length($p) ? "$p:$an" : $an;
        $attrs->{"{}$an"} = {
            Name => $qname, LocalName => $an, Prefix => $p,
            NamespaceURI => $ns_uri, Value => "$v",
        };
    }
    {   NamespaceURI => $ns, LocalName => $ln,
        Name => length($pfx) ? "$pfx:$ln" : $ln,
        Prefix => $pfx, Attributes => $attrs,
    };
}

sub emit_event_stream ($handler) {
    $handler->start_document({});

    # Single document root so XML::LibXML::SAX parse_file succeeds (exactly
    # one top-level element is required for XML 1.0 well-formedness).  BSAX
    # supports multi-root streams but the reference ground-truth parser in
    # this test is XML, so keep one outer <amin:profile> only.
    $handler->start_element(_el($NS_AMIN,'amin','profile',
        'xmlns:amin' => $NS_AMIN,
        'xmlns:bc' => $NS_BC,
        'xmlns:sox' => $NS_SOX,
        'amin:id' => 'metal-node-init-profile',
        'amin:version' => '0.1.0'));

    # 1. bc:* namespace element (NS_BITCACHE=4) — object/signer envelope from
    #    the legacy Bitcache 2014 design, should be encoded with 4-bit NS=4
    #    inline + NAME_ID=68 ("object") → 1 byte each (not escaped).
    $handler->start_element(_el($NS_BC,'bc','object',
        'bc:hash' => 'aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccdd',
        'bc:date' => '1728400000'));
    $handler->start_element(_el($NS_BC,'bc','signer',
        'bc:name' => 'Alice Node <alice@projectamin.org>',
        'bc:ref'  => 'bitcache:blake3:deadbeefcafebabe0001'));
    $handler->characters({Data => "signer-signature"});
    $handler->end_element(_el($NS_BC,'bc','signer'));
    $handler->end_element(_el($NS_BC,'bc','object'));

    # 2. ainit stage NAME_IDs — `stage` should be vocab index 87 (1 byte).
    for (
        [1, 'hwcheck'   => 'n143-rack2'],
        [2, 'fwupdate'  => 'n143-rack2'],
        [3, 'storageinit' => 'n143-rack2', '/dev/nvme0n1'],
    ) {
        my ($order, $name, $node, $slab) = @$_;
        $slab //= '';
        my %attrs = (
            'amin:order'   => $order,
            'amin:stage'   => $name,
            'amin:node_id' => $node,
        );
        $attrs{'amin:slab_dev'} = $slab if length $slab;
        $handler->start_element(_el($NS_AMIN,'amin','stage', %attrs));
        $handler->end_element(_el($NS_AMIN,'amin','stage'));
    }

    # 3. sandbox + net names (indices 96, 102-106).
    $handler->start_element(_el($NS_AMIN,'amin','sandbox',
        'amin:cpu_max' => '200000 1000000',
        'amin:memory_high' => '8G',
        'amin:landlock_ro' => '/usr:/lib:/etc/ssl',
        'amin:seccomp' => 'bitcache:blake3:seccomp-abcdef123'));
    $handler->end_element(_el($NS_AMIN,'amin','sandbox'));
    $handler->start_element(_el($NS_AMIN,'amin','lb',
        'amin:vip' => '10.0.0.1:80',
        'amin:backends' => '10.1.0.2:8080,10.1.0.3:8080'));
    $handler->end_element(_el($NS_AMIN,'amin','lb'));
    $handler->start_element(_el($NS_AMIN,'amin','netpolicy',
        'amin:vpc' => 'tenant-prod',
        'amin:subnet' => '10.2.0.0/24'));
    $handler->end_element(_el($NS_AMIN,'amin','netpolicy'));

    # 4. NS_ESCAPE — sox:* custom namespace element (Corp X extensibility,
    #    NOT closed-world vocab; should survive on NS_ESCAPE=15 length-prefixed
    #    UTF-8 URI inline path.
    $handler->start_element(_el($NS_SOX,'sox','audit-trail',
        'sox:id' => 'corpx-audit-001',
        'sox:stage' => 'netpolicy-approved'));
    $handler->characters({Data => "sox-log-marker-xyz"});
    $handler->end_element(_el($NS_SOX,'sox','audit-trail'));

    $handler->end_element(_el($NS_AMIN,'amin','profile'));
    $handler->end_document({});
}

# ── 1. BSAX encode
my $bsax = Amin::Handler::BSAX->new();
emit_event_stream($bsax);
my $BIN = $bsax->output();
ok length($BIN) > 8, "encode " . length($BIN) . " B";

# ── 2. Ground truth: XML::LibXML::SAX parse of the same stream
my $w = Amin::Handler::Writer->new();
emit_event_stream($w);
my $XML = $w->output();

my @xml;
{
    open my $fh, '>', \(my $buf);
    print $fh $XML; close $fh;
    open my $rfh, '<', \$buf;
    my $h = Amin::Test::RecordingHandler->new;
    my $p = XML::LibXML::SAX->new(Handler => $h);
    $p->parse_file($rfh);
    @xml = $h->captured->@*;
}

# ── 3. BSAX decode via Generator::BSAX → RecordingHandler
my @bin;
{
    my $h = Amin::Test::RecordingHandler->new;
    my $g = Amin::Generator::BSAX->new(Handler => $h);
    $g->parse_bytes($BIN);
    @bin = $h->captured->@*;
}

# ── 4. Strip doc bookends (t/11 pattern)
sub strip_doc_bookends (@ev) {
    while (@ev && $ev[0]  && $ev[0]  eq 'start_document') { shift @ev }
    while (@ev && $ev[-1] && $ev[-1] eq 'end_document')   { pop   @ev }
    @ev;
}
@xml = strip_doc_bookends(@xml);
@bin = strip_doc_bookends(@bin);

# ── 5. Event count parity + per-event assertion (same as t/11)
is scalar(@bin), scalar(@xml),
   "event count (xml=" . scalar(@xml) . ", bsax=" . scalar(@bin) . ")";
for my $i (0..$#xml) {
    is $bin[$i], $xml[$i], "event[$i]: binary decode ≡ xml sax parse";
}

# ── 6. Spot-check: the sox custom namespace DID reach RecordingHandler
#         (i.e. NS_ESCAPE=15 roundtrip is NOT dropped by Generator allow-list)
my $sox_seen = 0;
for my $ev (@bin) {
    next unless ref($ev) eq 'ARRAY' && $ev->[0] eq 'start_element';
    ++$sox_seen if ($ev->[1]{NamespaceURI} // '') eq $NS_SOX;
}
cmp_ok($sox_seen, '>=', 1,
   "NS_ESCAPE custom namespace (sox:*) element reached RecordingHandler after BSAX decode");

done_testing;
