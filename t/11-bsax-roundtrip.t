#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempfile);
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

# Amin::Test::RecordingHandler replaces the ~50-line duplicated inline
# RecordingHandler class that historically lived here and in t/12.
# Event access API: $r->captured  → arrayref  (filter-local; no our @CAPTURE
# pollution between subtests, no manual `@Captured = ()` reset needed).

# ── Shared NS + element builder
my $NS_AMIN = 'http://projectamin.org/ns/2026/';
my $NS_UI   = 'http://projectamin.org/ns/ui/1';
my $NS_MAP  = 'http://projectamin.org/ns/map/1';

sub _ns_of_prefix ($p) {
    return $NS_AMIN if $p eq 'amin';
    return $NS_UI   if $p eq 'ui';
    return $NS_MAP  if $p eq 'map';
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
    $handler->start_element(_el($NS_AMIN,'amin','profile',
        'xmlns:amin'=>$NS_AMIN,'xmlns:ui'=>$NS_UI,'xmlns:map'=>$NS_MAP,
        'amin:id'=>'io.projectamin.apps.shop-ui','amin:version'=>'0.1.0'));
    $handler->start_element(_el($NS_UI,'ui','app',
        'amin:id'=>'shop-ui','title'=>'Fabric Shop'));
    # status 5 attrs (hot event)
    $handler->start_element(_el($NS_AMIN,'amin','status',
        'amin:kind'=>'success','amin:rc'=>'0','amin:pid'=>'38421',
        'amin:duration'=>'0.128','amin:exit_kind'=>'ok'));
    $handler->end_element(_el($NS_AMIN,'amin','status'));
    # stream + 1 line chars
    $handler->start_element(_el($NS_AMIN,'amin','stream','amin:channel'=>'out'));
    $handler->characters({Data=>"gcc -O3 -c foo.c -o foo.o"});
    $handler->end_element(_el($NS_AMIN,'amin','stream'));
    # map server
    $handler->start_element(_el($NS_MAP,'map','server',
        'map:id'=>'edge-01','map:flavor'=>'metal-amd-96c','map:status'=>'success'));
    $handler->end_element(_el($NS_MAP,'map','server'));
    # ui text + chars
    $handler->start_element(_el($NS_UI,'ui','text','ui:kind'=>'headline'));
    $handler->characters({Data=>"metal-amd-96c"});
    $handler->end_element(_el($NS_UI,'ui','text'));
    $handler->end_element(_el($NS_UI,'ui','app'));
    $handler->end_element(_el($NS_AMIN,'amin','profile'));
    $handler->end_document({});
}

# 1. BSAX encode
my $bsax = Amin::Handler::BSAX->new();
emit_event_stream($bsax);
my $BIN = $bsax->output();
ok length($BIN) > 8, "encode " . length($BIN) . " B";

# 2. XML encode (Writer) — ground truth
my $w = Amin::Handler::Writer->new();
emit_event_stream($w);
my $XML = $w->output();
ok length($XML) > length($BIN),
   "wire reduction: " . length($BIN) . " vs " . length($XML) .
   " B (" . int(100*length($BIN)/length($XML)) . "% of XML)";

# 3. XML decode → capture (tempfile to avoid in-memory-unicode-open issues)
my @xml;
{
    my ($fh, $path) = tempfile(UNLINK => 1, TMPDIR => 1);
    print $fh $XML; close $fh;
    my $h = Amin::Test::RecordingHandler->new;
    my $p = XML::LibXML::SAX->new(Handler => $h);
    $p->parse_file($path);
    @xml = $h->captured->@*;
}

# 4. BSAX decode → capture
my @bin;
{
    my $h = Amin::Test::RecordingHandler->new;
    my $g = Amin::Generator::BSAX->new(Handler => $h);
    $g->parse_bytes($BIN);
    @bin = $h->captured->@*;
}

# 5. Strip duplicate start_document/end_document events (XML parser can emit
#    extras via parse_file internal prolog handling; we care about event parity
#    of the stream, not the prolog wrapper)
sub strip_doc_bookends (@ev) {
    # Remove leading 'start_document' x 1..N and trailing 'end_document' x1..N
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

# 6. XML fallback → same as XML parser
my @fb;
{
    my $h = Amin::Test::RecordingHandler->new;
    my $g = Amin::Generator::BSAX->new(Handler => $h);
    $g->parse_bytes($XML);
    @fb = strip_doc_bookends($h->captured->@*);
}
is scalar(@fb), scalar(@xml), "XML fallback produces same event count";

# 7. Streaming parity (BSAX is ONLY a streamed protocol): feeding the same
#    bytes one byte at a time through feed()/finish() must emit EXACTLY the
#    same event sequence as the one-shot parse_bytes() convenience.  This is
#    what proves no event is lost or duplicated at a chunk boundary.
{
    my $href = Amin::Test::RecordingHandler->new;
    Amin::Generator::BSAX->new(Handler => $href)->parse_bytes($BIN);

    my $hchunk = Amin::Test::RecordingHandler->new;
    my $gchunk = Amin::Generator::BSAX->new(Handler => $hchunk);
    for my $i (0 .. length($BIN) - 1) { $gchunk->feed(substr($BIN, $i, 1)) }
    $gchunk->finish;

    is scalar($hchunk->captured->@*), scalar($href->captured->@*),
       "feed(1-byte chunks) event count ≡ parse_bytes";
    is $hchunk->captured, $href->captured,
       "feed(1-byte chunks) event sequence ≡ parse_bytes";
}

# 8. Strict XML::SAX parity for the event kinds that are NOT start/end element.
#    A hand-built stream exercises the three arms the aligned decoder must fire
#    exactly once each, in document order:
#      0xA0 IWS        → ignorable_whitespace   (must NOT fold into `characters`)
#      0xC0 PI         → processing_instruction  (escaped/PROHIBITED target path)
#      0xE0 DICT_ENTRY → no handler event; interns id → name, transparently
#                        resolved by a LATER NAME_ID reference (_lex_name).
{
    my $leb = sub {                     # LEB128 u32, byte-string form
        my $n = shift;
        my $s = '';
        do { my $b = $n & 0x7F; $n >>= 7; $b |= 0x80 if $n; $s .= chr($b) } while $n;
        $s;
    };
    my $lpfx = sub { $leb->(length $_[0]) . $_[0] };   # LEB length + raw bytes

    my $DICT_ID = 200;                  # ≥128 ⇒ never collides with a vocab slot
    my $s  = "AMINBSA1";                # magic
    $s .= "\x00";                       # StartDoc
    # DICT_ENTRY: flags[4] = NS_ID (AMIN=1) ⇒ tag 0xF0; LEB id; len-prefixed name
    $s .= "\xF0" . $leb->($DICT_ID) . $lpfx->('frobnicate');
    # StartEl: NS present + 0 attrs ⇒ tag 0x50; NS byte 0x10 (AMIN); interned id
    $s .= "\x50" . "\x10" . $leb->($DICT_ID);
    $s .= "\x82" . "hi";               # Chars "hi"
    $s .= "\xA3" . "\n  ";             # IWS
    # PI: target id == ESCAPE ⇒ inline len-prefixed target, then data blob
    $s .= "\xC0" . $leb->(Amin::Generator::BSAX::ESCAPE())
        . $lpfx->('xml-stylesheet') . $lpfx->('type="text/xsl"');
    $s .= "\x60";                       # EndEl
    $s .= "\x20";                       # EndDoc

    my $want = [
        'start_document',
        [start_element => { LocalName => 'frobnicate',
                            NamespaceURI => $NS_AMIN, Attributes => [] }],
        [characters => 'hi'],
        [ignorable_whitespace => "\n  "],
        [processing_instruction => { Target => 'xml-stylesheet',
                                     Data   => 'type="text/xsl"' }],
        [end_element => { LocalName => 'frobnicate', NamespaceURI => $NS_AMIN }],
        'end_document',
    ];

    my $h = Amin::Test::RecordingHandler->new;
    Amin::Generator::BSAX->new(Handler => $h)->parse_bytes($s);
    is $h->captured, $want,
       "IWS→ignorable_whitespace, PI→processing_instruction, DICT name resolves";

    # The same stream fed one byte at a time must be identical — interning,
    # IWS and PI must all survive chunk boundaries intact.
    my $hc = Amin::Test::RecordingHandler->new;
    my $gc = Amin::Generator::BSAX->new(Handler => $hc);
    for my $i (0 .. length($s) - 1) { $gc->feed(substr($s, $i, 1)) }
    $gc->finish;
    is $hc->captured, $want, "IWS/PI/DICT survive 1-byte chunked feed";
}

done_testing();
