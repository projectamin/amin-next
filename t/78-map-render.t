#!/usr/bin/env perl
# `amin map` is a map frontend, not an XML passthrough:
#   --out=svg  → standalone SVG document emitted as svg:* events by the
#                spec-selected Amin::Map::Target::SVG (full graph only after
#                the source document is exhausted)
#   --out=dot  → standalone DOT text on the map-dot stream
#   --out=xml  → profile in / profile out, annotated with map:node/map:link
#
# Also pins the contract seam: which class serves each --out value is declared
# in machine_spec.xml (<map-dialect>), exactly like <ui-dialect>.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd qw(abs_path);
use lib dirname(__FILE__) . '/../perl-lib';

use XML::LibXML;
use Amin::Machine::MachineSpec;

my $ROOT = abs_path(dirname(__FILE__) . '/..');
my $AMIN = "$ROOT/bin/amin";
my $XML  = "$ROOT/examples/apps/shop-ui/map+ui.xml";
my $SVG_NS = 'http://www.w3.org/2000/svg';
my $MAP_NS = 'http://projectamin.org/ns/map/1';
my $AMIN_NS = 'http://projectamin.org/ns/2026/';

$ENV{PERL5LIB} = join ':', "$ROOT/perl-lib", (grep length, $ENV{PERL5LIB} // '');

sub run_bin {
    open(my $p, '-|', $^X, '-I', "$ROOT/perl-lib", '-I', "$ROOT/local/lib/perl5", @_)
        or die "popen: $!";
    local $/; my $o = <$p>; close $p;
    ($o, $? >> 8);
}

sub xpath ($doc) {
    my $xc = XML::LibXML::XPathContext->new($doc);
    $xc->registerNs('s', $SVG_NS);
    $xc->registerNs('m', $MAP_NS);
    $xc->registerNs('a', $AMIN_NS);
    return $xc;
}

# ── the dialect binding is a spec fact ────────────────────────────────────
my $spec = Amin::Machine::MachineSpec->new->spec;
is($spec->{map_dialects}{svg}{class}, 'Amin::Map::Target::SVG',
   'spec binds --out=svg to Amin::Map::Target::SVG');
is($spec->{map_dialects}{dot}{class}, 'Amin::Map::Target::DOT',
   'spec binds --out=dot to Amin::Map::Target::DOT');
ok(!exists $spec->{map_dialects}{xml},
   '--out=xml selects no map dialect (profile annotation path)');

# ── --out=svg: a real, well-formed SVG document ───────────────────────────
my ($svg, $rc) = run_bin($AMIN, 'map', $XML, '--out=svg');
is($rc, 0, 'map --out=svg exits 0');
like($svg, qr{\A<\?xml[^>]*\?>\s*<svg\b}, 'output opens as an SVG document');
my $sdom = eval { XML::LibXML->load_xml(string => $svg) };
is($@, '', 'SVG output is well-formed XML');
my $sroot = $sdom->documentElement;
is($sroot->namespaceURI, $SVG_NS, 'root is in the SVG namespace');
is($sroot->localName, 'svg', 'root localName is svg');
like($sroot->getAttribute('viewBox'), qr{\A0 0 \d+(\.\d+)? \d+(\.\d+)?\z},
     'root carries a numeric viewBox');

my $sx = xpath($sdom);
my @regions = $sx->findnodes('//s:g[@class="region"]');
is(scalar @regions, 2, 'two regions rendered');
my @s_nodes = $sx->findnodes('//s:g[contains(@class,"node")]');
is(scalar @s_nodes, 8, 'eight nodes rendered');
my @lines = $sx->findnodes('//s:line');
is(scalar @lines, 5, 'five links rendered');
my @ids = map { $_->getValue } $sx->findnodes('//s:g[contains(@class,"node")]/@data-id');
is(\@ids, [qw(prod-edge-01 prod-edge-02 prod-app-01 prod-app-02
              prod-db-01 prod-store-01 ios-store-3127 droid-scan-0088)],
    'nodes render in document order');
my @text = map { $_->textContent } $sx->findnodes('//s:text');
ok((grep { $_ eq 'prod-edge-01' } @text), 'node id is drawn as SVG text');
ok((grep { $_ eq 'c2.metal.24' } @text), 'flavor is drawn as SVG text');

my @costs = map { $_->textContent }
            $sx->findnodes('//s:g[@class="edge-labels"]/s:text');
is(scalar @costs, 5, 'every link carries a cost label');
is([sort @costs], [sort qw(1 1 5 5 10)], 'cost labels match the declared costs');
my @anchors = map { $_->getValue }
              $sx->findnodes('//s:g[@class="edge-labels"]/s:text/@text-anchor');
is(\@anchors, [('middle') x 5], 'cost labels are centred on the link');

# A label must not land inside a card: links are centre-to-centre, so the
# midpoint of a shortcut can sit on an unrelated node.
use Amin::Map::Target::Base;
my $tgt = Amin::Map::Target::Base->new;
my %pos = (
    a => { x => 0,   y => 0, w => 100, h => 50, cx => 50,  cy => 25 },
    m => { x => 150, y => 0, w => 100, h => 50, cx => 200, cy => 25 },
    b => { x => 300, y => 0, w => 100, h => 50, cx => 350, cy => 25 },
);
my ($lx, $ly) = $tgt->edge_label_point(\%pos, 'a', 'b');
is([$lx, $ly], [125, 25],
   'label sits in the free gap before the occluding card, not its midpoint');

# ── --out=dot: standalone Graphviz text ───────────────────────────────────
my ($dot, $drc) = run_bin($AMIN, 'map', $XML, '--out=dot');
is($drc, 0, 'map --out=dot exits 0');
like($dot, qr{\Adigraph amin_topology \{}m, 'DOT output opens a digraph');
like($dot, qr{subgraph cluster_europe_west1 \{}m, 'DOT renders a region cluster');
like($dot, qr{"prod-edge-01" -> "prod-app-01" \[label="1"}, 'DOT renders an edge');

# ── --out=xml: profile in, profile out ────────────────────────────────────
my ($xml, $xrc) = run_bin($AMIN, 'map', $XML, '--out=xml');
is($xrc, 0, 'map --out=xml exits 0');
my $xdom = eval { XML::LibXML->load_xml(string => $xml) };
is($@, '', 'XML output is well-formed');
my $xroot = $xdom->documentElement;
is($xroot->namespaceURI, $AMIN_NS, 'XML mode keeps the amin profile root');
is($xroot->localName, 'profile', 'XML mode is profile-in/profile-out');

my $xx = xpath($xdom);
my @m_nodes = $xx->findnodes('//m:node');
is(scalar @m_nodes, 8, 'profile output annotates eight map:node events');
my @m_links = $xx->findnodes('//m:link[@a][@b]');
cmp_ok(scalar @m_links, '>=', 5,
    'profile output includes map:link annotations');
my ($derived) = $xx->findnodes('//m:link[@a="prod-edge-01"][@b="prod-app-01"]');
ok($derived, 'derived link carries both endpoints');
is($derived->getAttribute('cost'), '1', 'derived link carries its cost');
is($derived->getAttribute('color'), '#00b4d8', 'derived link carries its color');

# ── render mode still returns a profile (--out is map-only) ───────────────
my ($render, $rrc) = run_bin($AMIN, 'render', $XML);
is($rrc, 0, 'render exits 0');
my $rdom = eval { XML::LibXML->load_xml(string => $render) };
is($@, '', 'render output is well-formed XML');
is($rdom->documentElement->localName, 'profile',
    'render keeps profile-in/profile-out even with the default map_out');

done_testing;
