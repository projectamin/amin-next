#!/usr/bin/env perl
# sec: namespace + closed-world NAME_IDs (NS_SEC=5) — Perl side of the
# payload-neutral post-quantum E2EE vocabulary (Double Ratchet + PQXDH).
#
# Proves the Perl Handler/Generator::BSAX mirrors are 1:1 with the Rust
# bsax/src/vocab.rs BY_ID slice at the SAME indices (122..136, ESCAPE=137),
# that sec: rides the first-class NS_ID=5 slot rather than the NS_ESCAPE
# length-prefixed path, and that a sec: event stream survives a full
# BSAX encode → decode roundtrip identically to the XML path.
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

my $NS_AMIN = 'http://projectamin.org/ns/2026/';
my $NS_SEC  = 'http://projectamin.org/ns/sec/1';

sub _ns_of_prefix ($p) {
    return $NS_AMIN if $p eq 'amin';
    return $NS_SEC  if $p eq 'sec';
    return '';
}

sub _el ($ns,$pfx,$ln,%a) {
    my $attrs = {};
    while (my ($k,$v) = each %a) {
        my ($p,$an) = ($k =~ /^([a-z]+):(.+)$/) ? ($1,$2) : ($pfx,$k);
        my $qname = length($p) ? "$p:$an" : $an;
        $attrs->{"{}$an"} = {
            Name => $qname, LocalName => $an, Prefix => $p,
            NamespaceURI => _ns_of_prefix($p), Value => "$v",
        };
    }
    {   NamespaceURI => $ns, LocalName => $ln,
        Name => length($pfx) ? "$pfx:$ln" : $ln,
        Prefix => $pfx, Attributes => $attrs,
    };
}

# ── 1. Perl vocab is 1:1 with Rust bsax/src/vocab.rs BY_ID ───────────────────
# Rust asserts BY_ID.len() == 137 and BY_ID[122] == b"seal" .. BY_ID[136] ==
# b"require".  Assert the Perl mirrors land on exactly the same slots.
is Amin::Handler::BSAX::ESCAPE(),        137, 'Handler::BSAX ESCAPE == 137 (= BY_ID.len)';
is Amin::Generator::BSAX::ESCAPE(),      137, 'Generator::BSAX ESCAPE == 137';
is Amin::Handler::BSAX::NS_SEC(),          5, 'Handler::BSAX NS_SEC == 5';
is Amin::Generator::BSAX::NS_SEC(),        5, 'Generator::BSAX NS_SEC == 5';

is $Amin::Handler::BSAX::ID{seal},      122, 'Handler::BSAX sec:seal      => 122';
is $Amin::Handler::BSAX::ID{sealed},    123, 'Handler::BSAX sec:sealed    => 123';
is $Amin::Handler::BSAX::ID{ratchet},   126, 'Handler::BSAX sec:ratchet   => 126';
is $Amin::Handler::BSAX::ID{prev_count},127, 'Handler::BSAX sec:prev_count=> 127';
is $Amin::Handler::BSAX::ID{msg_index}, 128, 'Handler::BSAX sec:msg_index => 128';
is $Amin::Handler::BSAX::ID{require},   136, 'Handler::BSAX sec:require   => 136';

is $Amin::Generator::BSAX::NAMEBYID{122}, 'seal',       'Generator::BSAX 122 => seal';
is $Amin::Generator::BSAX::NAMEBYID{136}, 'require',    'Generator::BSAX 136 => require';
is $Amin::Generator::BSAX::NAMEBYID{126}, 'ratchet',    'Generator::BSAX 126 => ratchet';

# ── 2. NS_ID=5 is first-class: no per-element URI on the wire ───────────────
# Encode one <sec:sealed sec:msg_index="7"/> under the sec: URI (known →
# NAME_ID + 4-bit NS) and under an unknown URI (NS_ESCAPE=15 → length-prefixed
# URI inline every element).  The escaped form must pay the URI bytes.
sub _encode_one ($ns_uri) {
    my $h = Amin::Handler::BSAX->new;
    $h->start_document({});
    $h->start_element(_el($ns_uri,'sec','sealed', 'sec:msg_index' => '7'));
    $h->end_element(_el($ns_uri,'sec','sealed'));
    $h->end_document({});
    $h->output;
}
my $bytes_sec = _encode_one($NS_SEC);
my $bytes_esc = _encode_one('https://corp.example.test/ns/zz/v1');
ok length($bytes_sec) < length($bytes_esc),
   'sec: uses NS_ID=5 inline (no URI bytes) — smaller than the NS_ESCAPE form '
   . "(" . length($bytes_sec) . " vs " . length($bytes_esc) . " B)";

# ── 3. Full BSAX roundtrip parity for a sec: stream ────────────────────────
sub emit_event_stream ($handler) {
    $handler->start_document({});
    $handler->start_element(_el($NS_AMIN,'amin','profile',
        'xmlns:amin'=>$NS_AMIN,'xmlns:sec'=>$NS_SEC,
        'amin:id'=>'sec-e2ee','amin:version'=>'0.1.0'));
    # A sealed message: header fields as attrs, ciphertext as chars.
    $handler->start_element(_el($NS_SEC,'sec','sealed',
        'sec:ratchet'    => 'aabbccdd00112233445566778899aabb',
        'sec:prev_count' => '0',
        'sec:msg_index'  => '7'));
    $handler->characters({Data=>"q2Fzjc0F+s2vZC1jaXBoZXJ0ZXh0LXg9"});
    $handler->end_element(_el($NS_SEC,'sec','sealed'));
    # The inner plaintext wrapper the RatchetSeal filter fills.
    $handler->start_element(_el($NS_SEC,'sec','seal','sec:session'=>'bitcache:blake3:deadbeef0001'));
    $handler->characters({Data=>"plaintext-inside-the-ratchet"});
    $handler->end_element(_el($NS_SEC,'sec','seal'));
    $handler->end_element(_el($NS_AMIN,'amin','profile'));
    $handler->end_document({});
}

my $bsax = Amin::Handler::BSAX->new();
emit_event_stream($bsax);
my $BIN = $bsax->output();
ok length($BIN) > 8, "encode " . length($BIN) . " B";

my $w = Amin::Handler::Writer->new();
emit_event_stream($w);
my $XML = $w->output();

my @xml;
{
    open my $fh, '>', \(my $buf);
    print $fh $XML; close $fh;
    open my $rfh, '<', \$buf;
    my $h = Amin::Test::RecordingHandler->new;
    XML::LibXML::SAX->new(Handler => $h)->parse_file($rfh);
    @xml = $h->captured->@*;
}
my @bin;
{
    my $h = Amin::Test::RecordingHandler->new;
    Amin::Generator::BSAX->new(Handler => $h)->parse_bytes($BIN);
    @bin = $h->captured->@*;
}

sub strip_doc_bookends (@ev) {
    while (@ev && $ev[0]  && $ev[0]  eq 'start_document') { shift @ev }
    while (@ev && $ev[-1] && $ev[-1] eq 'end_document')   { pop   @ev }
    @ev;
}
@xml = strip_doc_bookends(@xml);
@bin = strip_doc_bookends(@bin);

is scalar(@bin), scalar(@xml),
   "event count (xml=" . scalar(@xml) . ", bsax=" . scalar(@bin) . ")";
for my $i (0..$#xml) {
    is $bin[$i], $xml[$i], "event[$i]: binary decode ≡ xml sax parse";
}

# Spot-check: the sec: element reached the handler under the sec: URI.
my $sec_seen = 0;
for my $ev (@bin) {
    next unless ref($ev) eq 'ARRAY' && $ev->[0] eq 'start_element';
    ++$sec_seen if ($ev->[1]{LocalName} // '') eq 'sealed'
                && ($ev->[1]{NamespaceURI} // '') eq $NS_SEC;
}
cmp_ok($sec_seen, '==', 1, 'sec:sealed reached RecordingHandler with the sec: namespace URI');

done_testing();
