#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempfile);
use lib dirname(__FILE__) . '/../perl-lib';
use lib '/tmp/amin-local/lib/perl5/x86_64-linux-gnu-thread-multi';
use lib '/tmp/amin-local/lib/perl5';

sub load ($mod) { eval "require $mod; $mod->import; 1" }
ok(load('Amin::Handler::Writer'),  'load Writer');
ok(load('Amin::Handler::BSAX'),    'load Handler::BSAX');
ok(load('Amin::Generator::BSAX'),  'load Generator::BSAX');
ok(load('XML::LibXML::SAX'),       'load XML::LibXML::SAX')
    or skip_all('XML::LibXML::SAX required', 100);

# Recording Handler — captures SAX events with NAME-sorted attrs for parity.
package RecordingHandler {
    use v5.38; use warnings;
    our @Captured;
    sub new ($class, %a) { bless \%a, $class }
    sub start_document ($self,@) { push @Captured, 'start_document' }
    sub end_document   ($self,@) { push @Captured, 'end_document' }
    sub end_element    ($self,$e) {
        my $eln = $e->{LocalName} // $e->{Name} // '';
        $eln =~ s/^[^:]+://;
        push @Captured, [end_element => {
            LocalName    => $eln,
            NamespaceURI => $e->{NamespaceURI} // '',
        }];
    }
    sub characters     ($self,$d) {
        my $t = $d->{Data} // '';
        return unless length $t;
        # Normalize whitespace: Writer pretty-prints with indent/newline padding
        # around element content (e.g. "\n      gcc ...  \n"); the binary path
        # stores only the semantic character data.  Trim both so parity holds.
        $t =~ s/^\s+|\s+$//g;
        return unless length $t;
        push @Captured, [characters => $t];
    }
    sub start_element  ($self,$e) {
        my @attrs;
        for my $a (values %{ $e->{Attributes} // {} }) {
            # Drop xmlns:* namespace declarations — carried in BSAX via 4-bit
            # NS_ID inline bits, not as data attributes.
            my $n = $a->{Name} // '';
            next if $n =~ /^xmlns/;
            my $v = $a->{Value} // '';
            next unless length($v) || defined $a->{Value};
            # Semantic-local: strip any colon-prefix portion from LocalName
            # (different SAX parsers expose "prefix:name" vs {Prefix,name}
            # differently; contract parity is local-part + value only).
            my $ln = $a->{LocalName} // $n;
            $ln =~ s/^[^:]+://;
            push @attrs, { LocalName => $ln, Value => $v };
        }
        @attrs = sort { $a->{LocalName} cmp $b->{LocalName} } @attrs;
        my $eln = $e->{LocalName} // $e->{Name} // '';
        $eln =~ s/^[^:]+://;
        push @Captured, [start_element => {
            LocalName => $eln,
            NamespaceURI => $e->{NamespaceURI} // '',
            Attributes  => \@attrs,
        }];
    }
}

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
@RecordingHandler::Captured = ();
{
    my ($fh, $path) = tempfile(UNLINK => 1, TMPDIR => 1);
    print $fh $XML; close $fh;
    my $h = RecordingHandler->new;
    my $p = XML::LibXML::SAX->new(Handler => $h);
    $p->parse_file($path);
}
my @xml = @RecordingHandler::Captured;

# 4. BSAX decode → capture
@RecordingHandler::Captured = ();
{
    my $h = RecordingHandler->new;
    my $g = Amin::Generator::BSAX->new(Handler => $h);
    $g->parse_bytes($BIN);
}
my @bin = @RecordingHandler::Captured;

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
@RecordingHandler::Captured = ();
{
    my $h = RecordingHandler->new;
    my $g = Amin::Generator::BSAX->new(Handler => $h);
    $g->parse_bytes($XML);
}
my @fb = strip_doc_bookends(@RecordingHandler::Captured);
is scalar(@fb), scalar(@xml), "XML fallback produces same event count";

done_testing();
