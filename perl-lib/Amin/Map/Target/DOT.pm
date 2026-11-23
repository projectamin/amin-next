package Amin::Map::Target::DOT;

# The DOT dialect of the map target contract.  DOT is not XML, so the whole
# graph rides one <amin:stream channel="map-dot"> fragment (the same convention
# the source-oriented UI targets use).  Amin::Handler::DOT writes that text raw.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Map::Target::Base';

sub _esc ($s) {
    my $x = $s // '';
    $x =~ s/([\\"])/\\$1/g;
    return $x;
}

sub emit_graph ($self, $g, $h) {
    my ($regions) = $self->layout($g);

    my $out = "digraph amin_topology {\n";
    $out .= "  graph [rankdir=LR, bgcolor=\"#05080f\", fontname=\"Helvetica\"];\n";
    $out .= "  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\","
          . " fontcolor=\"#e8f0ff\", fillcolor=\"#111a2e\"];\n";

    for my $r ($regions->@*) {
        (my $cid = 'cluster_' . $r->{id}) =~ s/[^A-Za-z0-9_]/_/g;
        $out .= "  subgraph $cid {\n";
        $out .= "    label=\"" . _esc($r->{id}) . "\";\n";
        $out .= "    color=\"" . _esc($r->{accent}) . "\";\n";
        $out .= "    fontcolor=\"" . _esc($r->{accent}) . "\";\n";
        for my $id ($r->{ids}->@*) {
            my $n = $g->{nodes}{$id};
            my $label = _esc($id);
            $label .= '\n' . _esc($n->{flavor}) if length($n->{flavor} // '');
            $label .= '\n' . _esc($n->{location}) if length($n->{location} // '');
            $out .= '    "' . _esc($id) . '" [label="' . $label
                  . '", color="' . _esc($self->status_color($n->{status})) . '"];'
                  . "\n";
        }
        $out .= "  }\n";
    }

    for my $e ($g->{edges}->@*) {
        my ($a, $b) = ($e->{a} // '', $e->{b} // '');
        next unless length $a && length $b;
        my $color = length($e->{color} // '') ? $e->{color} : '#334155';
        $out .= '  "' . _esc($a) . '" -> "' . _esc($b) . '"'
              . ' [label="' . _esc($e->{cost}) . '", color="' . _esc($color) . '"];'
              . "\n";
    }
    $out .= "}\n";

    $self->emit_stream($h, 'map-dot', $out);
    return;
}

1;
