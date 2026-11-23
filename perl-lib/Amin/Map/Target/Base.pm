package Amin::Map::Target::Base;

# map: IR  →  one render dialect (SVG / DOT).  Same seam as Amin::UI::Target::*:
# the Dispatcher resolves a target from the spec's <map-dialect> entry and
# injects it into Map::Topology as `Render`.  Topology owns the graph; a target
# owns layout and markup.  emit_graph() runs once, at the document boundary,
# because layout needs the complete node/edge set — never at map-layer close
# (map: siblings need not be contiguous).

use v5.38; use warnings; use utf8; use experimental 'signatures';

use constant MAP_NS  => 'http://projectamin.org/ns/map/1';
use constant AMIN_NS => 'http://projectamin.org/ns/2026/';

# Deterministic card layout: regions stack vertically, nodes wrap three across.
use constant NODE_W     => 196;
use constant NODE_H     => 74;
use constant GAP_X      => 26;
use constant GAP_Y      => 24;
use constant COLS       => 3;
use constant MARGIN     => 36;
use constant REGION_PAD => 22;
use constant HEADER     => 36;
use constant REGION_GAP => 30;

our %STATUS_COLOR = (
    success => '#22c55e',
    failed  => '#ef4444',
    error   => '#ef4444',
    pending => '#f59e0b',
    unknown => '#64748b',
);

# Targets are stateless projections; the Dispatcher instantiates one per chain.
sub new ($class, @) { bless {}, $class }

sub status_color ($self, $s) {
    return $STATUS_COLOR{ $s // '' } // $STATUS_COLOR{pending};
}

# Stable region order: document order, then one synthetic bucket for nodes that
# were never declared inside a region.  Empty regions are kept (they still
# convey the network's shape).
sub regions ($self, $g) {
    my @regions;
    my %claimed;
    for my $r ($g->{regions}->@*) {
        my @ids = grep { $g->{nodes}{$_} } @{ $r->{nodes} // [] };
        $claimed{$_} = 1 for @ids;
        push @regions, {
            id     => $r->{id} // '',
            accent => length($r->{accent} // '') ? $r->{accent} : '#00b4d8',
            bg     => length($r->{bg}     // '') ? $r->{bg}     : '#0a0f1c',
            ids    => \@ids,
        };
    }
    my @orphan = sort grep { !$claimed{$_} } keys %{ $g->{nodes} };
    if (@orphan) {
        push @regions, { id => 'unassigned', accent => '#64748b',
                         bg => '#0a0f1c', ids => \@orphan };
    }
    return @regions;
}

# Assign every node a position.  Returns (regions, positions, width, height);
# the region records carry x/y/w/h and positions are id → card geometry.
sub layout ($self, $g) {
    my @regions = $self->regions($g);
    my %pos;
    my $y = MARGIN;
    my $max_w = 0;
    for my $r (@regions) {
        my $n = scalar $r->{ids}->@*;
        my $cols = $n ? ($n < COLS ? $n : COLS) : 1;
        my $rows = $n ? int(($n + COLS - 1) / COLS) : 0;
        my $w = 2 * REGION_PAD + $cols * NODE_W + ($cols - 1) * GAP_X;
        my $h = HEADER + 2 * REGION_PAD
              + $rows * NODE_H + ($rows > 1 ? ($rows - 1) * GAP_Y : 0);
        $r->{x} = MARGIN; $r->{y} = $y; $r->{w} = $w; $r->{h} = $h;
        for my $i (0 .. $n - 1) {
            my ($row, $col) = (int($i / COLS), $i % COLS);
            my $x = $r->{x} + REGION_PAD + $col * (NODE_W + GAP_X);
            my $ny = $r->{y} + HEADER + REGION_PAD + $row * (NODE_H + GAP_Y);
            $pos{ $r->{ids}[$i] } = {
                x => $x, y => $ny, w => NODE_W, h => NODE_H,
                cx => $x + NODE_W / 2, cy => $ny + NODE_H / 2,
                region => $r->{id},
            };
        }
        $max_w = $w if $w > $max_w;
        $y += $h + REGION_GAP;
    }
    my $width  = $max_w + 2 * MARGIN;
    my $height = ($y > MARGIN ? $y - REGION_GAP : MARGIN) + MARGIN;
    return (\@regions, \%pos, $width, $height);
}

# Where an edge's cost label can live.  Links run centre-to-centre and cards
# paint over them, so the geometric midpoint of a shortcut can sit inside an
# unrelated card.  Return the midpoint of the longest stretch of the segment no
# card covers (ties: earliest), falling back to the midpoint when fully covered.
sub edge_label_point ($self, $pos, $id_a, $id_b) {
    my ($pa, $pb) = ($pos->{$id_a}, $pos->{$id_b});
    my ($x0, $y0) = ($pa->{cx}, $pa->{cy});
    my ($dx, $dy) = ($pb->{cx} - $x0, $pb->{cy} - $y0);

    my @blocked;
    for my $p (values %$pos) {
        my ($xl, $xh) = _axis_span($x0, $dx, $p->{x}, $p->{x} + $p->{w});
        my ($yl, $yh) = _axis_span($y0, $dy, $p->{y}, $p->{y} + $p->{h});
        next unless defined $xl && defined $yl;
        my $lo = $xl > $yl ? $xl : $yl;
        my $hi = $xh < $yh ? $xh : $yh;
        push @blocked, [$lo, $hi] if $hi > $lo;
    }

    my ($blo, $bhi, $blen) = (0, 0, 0);
    my $cursor = 0;
    for my $iv (sort { $a->[0] <=> $b->[0] } @blocked) {
        my ($lo, $hi) = @$iv;
        if ($lo > $cursor && $lo - $cursor > $blen + 1e-9) {
            ($blo, $bhi, $blen) = ($cursor, $lo, $lo - $cursor);
        }
        $cursor = $hi if $hi > $cursor;
    }
    if ($cursor < 1 && 1 - $cursor > $blen) {
        ($blo, $bhi) = ($cursor, 1);
    }
    my $t = $blen ? ($blo + $bhi) / 2 : 0.5;
    return ($x0 + $dx * $t, $y0 + $dy * $t);
}

# t-interval (clipped to 0..1) where p0 + t*d lies within [lo, hi]; empty when
# it never does.
sub _axis_span ($p0, $d, $lo, $hi) {
    return ($p0 >= $lo && $p0 <= $hi) ? (0, 1) : () if $d == 0;
    my ($t1, $t2) = (($lo - $p0) / $d, ($hi - $p0) / $d);
    ($t1, $t2) = ($t2, $t1) if $t1 > $t2;
    $t1 = 0 if $t1 < 0;
    $t2 = 1 if $t2 > 1;
    return () if $t2 <= $t1;
    return ($t1, $t2);
}

# A text dialect's fragment rides as characters on an <amin:stream> element,
# exactly like the source-oriented UI targets; the artifact writer consumes it.
sub emit_stream ($self, $h, $channel, $text) {
    my $ns = AMIN_NS;
    $h->start_element({
        NamespaceURI => $ns, LocalName => 'stream',
        Name => 'amin:stream', Prefix => 'amin',
        Attributes => { "{$ns}channel" => {
            Name => 'amin:channel', LocalName => 'channel', Prefix => 'amin',
            NamespaceURI => $ns, Value => $channel } },
    });
    $h->characters({ Data => $text });
    $h->end_element({
        NamespaceURI => $ns, LocalName => 'stream', Name => 'amin:stream',
        Prefix => 'amin',
    });
    return;
}

sub emit_graph ($self, $graph, $handler) {
    die ref($self) . " must define emit_graph()\n";
}

1;
