#!/usr/bin/env perl
# t/64-content-xlsx.t — Amin::Content: document generation end to end.
#
#   OOXML::Package      deterministic ZIP writer/reader
#   XLSX::Writer        cells, styles, sheets, merges, freeze, autofilter
#   Content::Document   late filter: grammar → writer → CAS + bc:object
#   Handler/Generator::BSAX  amin:* grammar rides NS_AMIN; app filters keep
#                            their own namespace URI (no low-slot clash)
#
# The artifact is content-addressed, so equality of BLAKE3 hashes across two
# runs is the determinism assertion; part-level checks prove the bytes are a
# real spreadsheet, not just a stable blob.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp ();
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Content::XLSX::Writer;
require Amin::Content::OOXML::Package;
require Amin::Content::Format::Registry;
require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Handler::BSAX;
require Amin::Generator::BSAX;
require Amin::Log::Standard;
require Amin::Test::ZCapSign;

my $AMIN_NS    = 'http://projectamin.org/ns/2026/';
my $XLSX_MIME  = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

sub zcap_xml {
    my $token = Amin::Test::ZCapSign::make_zcap_token(ts => 1735689600);
    return qq{<amin:zcap amin:token="$token"/>};
}

sub run_doc ($inner, %o) {
    my $xml = qq{<?xml version="1.0"?>}
        . qq{<amin:profile xmlns:amin="$AMIN_NS">}
        . ($o{zcap} ? zcap_xml() : '')
        . $inner
        . qq{</amin:profile>};
    return Amin::Machine::Dispatcher->run(
        source_xml => $xml,
        mode       => $o{mode} // 'render',
        Handler    => Amin::Handler::Writer->new(indent => 0),
        Log        => Amin::Log::Standard->new(stderr => 0),
    );
}

sub attrs_of ($out, $prefix, $ln) {
    my $q = "\Q$prefix:$ln\E";
    my ($frag) = $out =~ /(<$q\b[^>]*>)/s or return {};
    my %a;
    while ($frag =~ /\Q$prefix\E:([\w.-]+)="([^"]*)"/g) { $a{$1} = $2 }
    return \%a;
}

# ── 1. XLSX writer: parts, values, styles and determinism ────────────────
sub build_workbook {
    my $w = Amin::Content::XLSX::Writer->new(title => 'Report', author => 'Amin');
    $w->start_document({ subject => 'unit' });
    $w->handle_start('style', { id => 'hdr', bold => 1, fill => '#DDEEFF', align => 'center' });
    $w->handle_start('sheet', { name => 'Data', 'tab-color' => '#00AA00' });
    $w->handle_start('column', { index => 1, width => 24 });

    $w->handle_start('row', { r => 1 });
    for my $cell ([A1 => 'Name', 'hdr'], [B1 => 'Value', 'hdr']) {
        $w->handle_start('cell', { ref => $cell->[0], type => 'string', style => $cell->[2] });
        $w->handle_text('cell', $cell->[1]);
        $w->handle_end('cell');
    }
    $w->handle_end('row');

    $w->handle_start('row', { r => 2 });
    $w->handle_start('cell', { ref => 'A2', type => 'string' });
    $w->handle_text('cell', 'alpha');
    $w->handle_end('cell');
    $w->handle_start('cell', { ref => 'B2', type => 'number' });
    $w->handle_text('cell', '12.5');
    $w->handle_end('cell');
    $w->handle_end('row');

    $w->handle_start('row', { r => 3 });
    $w->handle_start('cell', { ref => 'A3', type => 'date' });
    $w->handle_text('cell', '2026-11-17');
    $w->handle_end('cell');
    $w->handle_start('cell', { ref => 'B3', type => 'bool' });
    $w->handle_text('cell', 'true');
    $w->handle_end('cell');
    $w->handle_end('row');

    $w->handle_start('row', { r => 4 });
    $w->handle_start('cell', { ref => 'A4', type => 'formula' });
    $w->handle_text('cell', '=SUM(B2:B2)');
    $w->handle_end('cell');
    $w->handle_start('cell', { ref => 'B4', type => 'blank' });
    $w->handle_end('cell');
    $w->handle_end('row');

    $w->handle_start('freeze', { ref => 'A2' });
    $w->handle_start('autofilter', { ref => 'A1:B4' });
    $w->handle_start('merge', { ref => 'A6:B6' });
    $w->handle_end('sheet');

    $w->handle_start('sheet', { name => 'Notes' });
    $w->handle_start('row', {});
    $w->handle_start('cell', { type => 'string' });
    $w->handle_text('cell', 'n');
    $w->handle_end('cell');
    $w->handle_end('row');
    $w->handle_end('sheet');

    my ($bytes, $err) = $w->finish;
    return ($bytes, $err, $w);
}

my ($book, $book_err, $w) = build_workbook();
is $book_err, undef, 'writer: build succeeds';
ok defined $book && length $book, 'writer: bytes produced';
is $w->sheet_count, 2, 'writer: two sheets';
is $w->stats->{cells}, 9, 'writer: cell count (explicit blank included)';

my $parts = Amin::Content::OOXML::Package->read_parts($book);
my @want_parts = qw(
    [Content_Types].xml _rels/.rels docProps/app.xml docProps/core.xml
    xl/_rels/workbook.xml.rels xl/styles.xml xl/workbook.xml
    xl/worksheets/sheet1.xml xl/worksheets/sheet2.xml
);
is [sort keys %$parts], [sort @want_parts], 'reader: every OOXML part roundtrips';

my $sh1 = $parts->{'xl/worksheets/sheet1.xml'};
like $sh1, qr{<dimension ref="A1:B6"/>}, 'sheet: dimension spans cells + merge';
like $sh1, qr{<pane[^>]*topLeftCell="A2"[^>]*state="frozen"/>}, 'sheet: freeze pane';
like $sh1, qr{<autoFilter ref="A1:B4"/>}, 'sheet: autofilter';
like $sh1, qr{<mergeCell ref="A6:B6"/>}, 'sheet: merged range';
like $sh1, qr{<col min="1" max="1" width="24" customWidth="1"/>}, 'sheet: column width';
like $sh1, qr{<c r="A2" t="inlineStr"><is><t xml:space="preserve">alpha</t>}, 'cell: string';
like $sh1, qr{<c r="B2"><v>12.5</v></c>}, 'cell: number';
like $sh1, qr{<c r="A3" s="\d+"><v>\d+</v></c>}, 'cell: date as Excel serial';
like $sh1, qr{<c r="B3" t="b"><v>1</v></c>}, 'cell: boolean';
like $sh1, qr{<c r="A4"><f>SUM\(B2:B2\)</f><v>0</v></c>}, 'cell: formula';
like $sh1, qr{<c r="B4"/>}, 'cell: blank';

my $styles = $parts->{'xl/styles.xml'};
like $styles, qr{<b/>}, 'style: bold font';
like $styles, qr{patternType="solid"><fgColor rgb="FFDDEEFF"/>}, 'style: solid fill';
like $styles, qr{<alignment horizontal="center"/>}, 'style: alignment';
like $styles, qr{formatCode="yyyy-mm-dd"}, 'style: date numfmt';
like $parts->{'xl/workbook.xml'}, qr{<sheet name="Data" sheetId="1" r:id="rId1"/>},
    'workbook: first sheet';
like $parts->{'xl/workbook.xml'}, qr{<sheet name="Notes" sheetId="2" r:id="rId2"/>},
    'workbook: second sheet';
like $parts->{'docProps/core.xml'}, qr{<dc:title>Report</dc:title>}, 'props: title';
unlike $parts->{'docProps/core.xml'}, qr/2026-\d\d-\d\dT/, 'props: fixed timestamp only';
like $parts->{'docProps/core.xml'}, qr{1980-01-01T00:00:00Z}, 'props: deterministic clock';

my ($book2, undef) = build_workbook();
is $book2, $book, 'writer: identical bytes for identical input';

# ── 2. Dispatcher render: result + bc:object, no filesystem side effect ──
my $root = File::Temp::tempdir(CLEANUP => 1);
my $DOC = qq{<amin:document format="xlsx" title="Q3" root="$root" out="out/q3.xlsx">}
    . qq{<amin:style id="hdr" bold="1"/>}
    . qq{<amin:sheet name="Revenue"><amin:row r="1">}
    . qq{<amin:cell type="string" style="hdr">Region</amin:cell>}
    . qq{<amin:cell type="number">42</amin:cell>}
    . qq{</amin:row></amin:sheet></amin:document>};

my $render = run_doc($DOC, mode => 'render');
my $res  = attrs_of($render, 'amin', 'result');
my $bco  = attrs_of($render, 'bc', 'object');
is $res->{kind}, 'document', 'render: amin:result kind=document';
is $res->{format}, 'xlsx', 'render: format echoed';
is $res->{mime}, $XLSX_MIME, 'render: MIME type';
like $res->{hash}, qr/^[0-9a-f]{64}$/, 'render: 64-hex artifact hash';
is $res->{sheets}, '1', 'render: sheet count';
is $res->{rows}, '1', 'render: row count';
is $res->{cells}, '2', 'render: cell count';
is $bco->{kind}, 'document', 'render: bc:object kind=document';
is $bco->{hash}, $res->{hash}, 'render: bc:object carries the same hash';
is $bco->{path}, 'out/q3.xlsx', 'render: out path echoed';
ok !-e "$root/out/q3.xlsx", 'render: no file is written';

my $render2 = run_doc($DOC, mode => 'render');
is attrs_of($render2, 'amin', 'result')->{hash}, $res->{hash},
    'render: artifact hash is stable across runs';

my $two = run_doc(
    qq{<amin:document format="xlsx"><amin:sheet name="A">}
    . qq{<amin:row><amin:cell>1</amin:cell></amin:row>}
    . qq{</amin:sheet></amin:document>}
    . qq{<amin:document format="xlsx"><amin:sheet name="B">}
    . qq{<amin:row><amin:cell>2</amin:cell></amin:row>}
    . qq{</amin:sheet></amin:document>}, mode => 'render');
my @two_hashes = $two =~ /amin:hash="([0-9a-f]{64})"/g;
is scalar @two_hashes, 2, 'render: sibling documents each emit an artifact';
isnt $two_hashes[0], $two_hashes[1], 'render: sibling artifacts are distinct';

# The filter is scoped to (amin NS, document).  An application filter may use
# the same LocalName in its own URI and must pass through untouched.
my $APP_NS = 'https://apps.example.test/ns/doc/1';
my $app = run_doc(
    qq{<app:document xmlns:app="$APP_NS" app:format="acme">}
    . qq{<app:sheet name="App"/></app:document>}, mode => 'render');
unlike $app, qr/<amin:result\b/,
    'render: app-namespaced document is not captured by the core filter';
like $app, qr/<app:document\b/,
    'render: app-namespaced document passes through untouched';

# ── 3. Run mode: zcap + root confinement + real file ─────────────────────
my $run = run_doc($DOC, mode => 'run', zcap => 1);
my $rres = attrs_of($run, 'amin', 'result');
is $rres->{hash}, $res->{hash}, 'run: same artifact as render';
ok -f "$root/out/q3.xlsx", 'run: file materialised under amin:root';
my $on_disk = do {
    open my $fh, '<:raw', "$root/out/q3.xlsx" or die $!;
    local $/; <$fh>;
};
ok ref Amin::Content::OOXML::Package->read_parts($on_disk) eq 'HASH',
    'run: file is a readable OOXML package';
require Digest::BLAKE3;
my $hasher = Digest::BLAKE3::->new;
$hasher->add($on_disk);
is $hasher->hexdigest, $rres->{hash}, 'run: on-disk bytes hash to amin:hash';

# ── 4. Fail-closed: traversal, symlink escape, no zcap, bad format ───────
my $escape = run_doc(
    qq{<amin:document format="xlsx" root="$root" out="../escaped.xlsx">}
    . qq{<amin:sheet><amin:row><amin:cell>x</amin:cell></amin:row></amin:sheet>}
    . qq{</amin:document>}, mode => 'run', zcap => 1);
is attrs_of($escape, 'amin', 'result')->{exit_kind}, 'content_path',
    'run: ..-traversal is denied';
ok !-e "$root/../escaped.xlsx", 'run: traversal wrote nothing';

symlink '/etc', "$root/link" or die "symlink: $!";
my $sneak = run_doc(
    qq{<amin:document format="xlsx" root="$root" out="link/amin-escape.xlsx">}
    . qq{<amin:sheet><amin:row><amin:cell>x</amin:cell></amin:row></amin:sheet>}
    . qq{</amin:document>}, mode => 'run', zcap => 1);
is attrs_of($sneak, 'amin', 'result')->{exit_kind}, 'content_path',
    'run: symlinked subdirectory escape is denied';
ok !-e '/etc/amin-escape.xlsx', 'run: symlink wrote nothing';

require Amin::Auth::ZCap;
Amin::Auth::ZCap->_test_override_scope(undef);
my $nozcap = run_doc(
    qq{<amin:document format="xlsx" root="$root" out="out/nozcap.xlsx">}
    . qq{<amin:sheet><amin:row><amin:cell>x</amin:cell></amin:row></amin:sheet>}
    . qq{</amin:document>}, mode => 'run');
is attrs_of($nozcap, 'amin', 'result')->{exit_kind}, 'content_denied',
    'run: write without a zcap scope is denied';
ok !-e "$root/out/nozcap.xlsx", 'run: denied write wrote nothing';

my $bad = run_doc(
    qq{<amin:document format="pdf"><amin:sheet/></amin:document>},
    mode => 'render');
is attrs_of($bad, 'amin', 'result')->{exit_kind}, 'content_format',
    'unsupported format is a content_format error';

my $invalid = run_doc(
    qq{<amin:document><amin:sheet><amin:row>}
    . qq{<amin:cell type="number">not-a-number</amin:cell>}
    . qq{</amin:row></amin:sheet></amin:document>}, mode => 'render');
my $ierr = attrs_of($invalid, 'amin', 'result');
is $ierr->{exit_kind}, 'content_build', 'invalid cell type value fails the build';
like $ierr->{msg}, qr/invalid number/, 'build error names the bad cell';

my $dupe = run_doc(
    qq{<amin:document>}
    . qq{<amin:sheet name="S"/><amin:sheet name="s"/>}
    . qq{</amin:document>}, mode => 'render');
like attrs_of($dupe, 'amin', 'result')->{msg}, qr/duplicate sheet name/,
    'duplicate sheet names are rejected';

# ── 5. BSAX: grammar rides NS_AMIN; app vocab keeps its own URI ──────────
{
    package ContentRec;
    sub new ($class) { bless { events => [] }, $class }
    sub start_document   ($s, @)    { push $s->{events}->@*, ['start_document'] }
    sub end_document     ($s, @)    { push $s->{events}->@*, ['end_document'] }
    sub start_element    ($s, $e)   { push $s->{events}->@*, ['start_element', $e] }
    sub end_element      ($s, $e)   { push $s->{events}->@*, ['end_element', $e] }
    sub characters       ($s, $d)   { push $s->{events}->@*, ['characters', $d->{Data}] }
    sub ignorable_whitespace ($s, $d) { }
    sub processing_instruction ($s, @) { }
}

sub grammar_el ($ln, %a) {
    my $attrs = {};
    for my $k (keys %a) {
        $attrs->{"{}$k"} = {
            Name => "amin:$k", LocalName => $k, Prefix => 'amin',
            NamespaceURI => $AMIN_NS, Value => "$a{$k}",
        };
    }
    return {
        NamespaceURI => $AMIN_NS, LocalName => $ln, Name => "amin:$ln",
        Prefix => 'amin', Attributes => $attrs,
    };
}

sub app_el ($ln, %a) {
    my $attrs = {};
    for my $k (keys %a) {
        $attrs->{"{}$k"} = {
            Name => $k, LocalName => $k, Prefix => '',
            NamespaceURI => $APP_NS, Value => "$a{$k}",
        };
    }
    return {
        NamespaceURI => $APP_NS, LocalName => $ln, Name => $ln,
        Prefix => '', Attributes => $attrs,
    };
}

my $enc = Amin::Handler::BSAX->new;
$enc->start_document({});
$enc->start_element(grammar_el('document', format => 'xlsx', out => 'r.xlsx'));
$enc->start_element(grammar_el('sheet', name => 'Report', 'tab-color' => '#00FF00'));
$enc->start_element(grammar_el('cell', type => 'number', style => 'hdr'));
$enc->characters({ Data => '42' });
$enc->end_element(grammar_el('cell'));
$enc->end_element(grammar_el('sheet'));
# An application's own document grammar: SAME LocalName, own URI.  It must
# not be captured by the amin: grammar — this is the no-clash property that
# matters once third-party Perl/Rust filters are loaded.
$enc->start_element(app_el('document', format => 'acme'));
$enc->end_element(app_el('document'));
$enc->end_element(grammar_el('document'));
$enc->end_document({});

my $rec = ContentRec->new;
Amin::Generator::BSAX->new(Handler => $rec)->parse_bytes($enc->output);

my (@els, %attr_ns);
for my $ev ($rec->{events}->@*) {
    next unless $ev->[0] eq 'start_element';
    my $e = $ev->[1];
    push @els, $e;
    for my $a (values %{ $e->{Attributes} // {} }) {
        $attr_ns{ $e->{NamespaceURI} }{ $a->{LocalName} } = $a->{NamespaceURI};
    }
}
is [map { $_->{LocalName} } @els], [qw(document sheet cell document)],
    'bsax: element order survives';
is $els[0]{NamespaceURI}, $AMIN_NS, 'bsax: amin:document keeps the core NS';
is $els[1]{NamespaceURI}, $AMIN_NS, 'bsax: shared name sheet keeps amin NS';
is $els[2]{NamespaceURI}, $AMIN_NS, 'bsax: shared name cell keeps amin NS';
is $attr_ns{$AMIN_NS}{format}, $AMIN_NS, 'bsax: amin:format resolved to NS_AMIN';
is $attr_ns{$AMIN_NS}{'tab-color'}, $AMIN_NS, 'bsax: amin:tab-color resolved';
is $attr_ns{$AMIN_NS}{type},    $AMIN_NS, 'bsax: shared attr type resolves on amin';
is $attr_ns{$AMIN_NS}{style},   $AMIN_NS, 'bsax: amin:style attr';
is $els[3]{NamespaceURI}, $APP_NS, 'bsax: app document keeps its own URI';
is $attr_ns{$APP_NS}{format}, $APP_NS,
    'bsax: app-namespace attrs inherit the app URI, not amin';

# Wire contract: the grammar names were appended AFTER the sec:* region, so
# every earlier NAME_ID keeps its value.  Mirrors bsax/src/vocab.rs tests.
is Amin::Handler::BSAX::ESCAPE(),            172, 'bsax: ESCAPE == 172 (BY_ID.len)';
is Amin::Generator::BSAX::ESCAPE(),          172, 'bsax: Generator ESCAPE == 172';
is $Amin::Handler::BSAX::ID{document},       137, 'bsax: amin:document => 137';
is $Amin::Handler::BSAX::ID{freeze},         139, 'bsax: amin:freeze   => 139';
is $Amin::Handler::BSAX::ID{msg},            171, 'bsax: amin:msg      => 171';
is $Amin::Generator::BSAX::NAMEBYID{137}, 'document', 'bsax: 137 => document';
is $Amin::Generator::BSAX::NAMEBYID{171}, 'msg',      'bsax: 171 => msg';
is $Amin::Handler::BSAX::ID{seal},           122, 'bsax: sec:seal still 122';

is Amin::Content::Format::Registry::canonical('EXCEL'), 'xlsx',
    'registry: excel alias folds to xlsx';
is Amin::Content::Format::Registry::mime_for('excel'), $XLSX_MIME,
    'registry: alias carries the XLSX MIME';
ok !Amin::Content::Format::Registry::supported('pptx'),
    'registry: unregistered formats stay unsupported';

done_testing;
