package Amin::Map::Target::SVG;

# The SVG dialect of the map target contract.  Fragments are real svg:* SAX
# events (never markup built from a string), so the same projection can be
# serialized standalone by Amin::Handler::SVG or embedded in a profile by the
# XML writer.  Coordinates are layout facts owned here, not by the serializer.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Map::Target::Base';

use constant SVG_NS => 'http://www.w3.org/2000/svg';

use constant FONT_SANS => 'ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif';
use constant FONT_MONO => 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

sub _text ($self, $h, $s) { $h->characters({ Data => '' . $s }) }

sub _el ($self, $h, $name, $a, $body = undef) {
    my $ns = SVG_NS;
    my $attrs = { map {; "{}" . $_ => +{ Name => $_, LocalName => $_,
        Prefix => '', NamespaceURI => '', Value => '' . $a->{$_} } } keys %$a };
    $h->start_element({ NamespaceURI => $ns, LocalName => $name,
        Name => $name, Prefix => '', Attributes => $attrs });
    $body->($h) if $body;
    $h->end_element({   NamespaceURI => $ns, LocalName => $name,
        Name => $name, Prefix => '' });
}

sub emit_graph ($self, $g, $h) {
    my ($regions, $pos, $w, $ht) = $self->layout($g);

    $self->_el($h, 'svg', {
        xmlns   => SVG_NS,
        width   => $w,
        height  => $ht,
        viewBox => "0 0 $w $ht",
        role    => 'img',
    }, sub {
        $self->_el($h, 'title', {}, sub { $self->_text($h, 'Amin fabric topology') });
        $self->_el($h, 'rect', {
            x => 0, y => 0, width => $w, height => $ht, fill => '#05080f',
        });

        # Edges first: cards paint over the line ends, so links read as
        # connecting the nodes rather than floating between them.
        $self->_el($h, 'g', { class => 'edges' }, sub {
            for my $e ($g->{edges}->@*) {
                my ($a, $b) = ($e->{a} // '', $e->{b} // '');
                next unless $pos->{$a} && $pos->{$b};
                my $stroke = length($e->{color} // '') ? $e->{color} : '#334155';
                $self->_el($h, 'line', {
                    x1 => $pos->{$a}{cx}, y1 => $pos->{$a}{cy},
                    x2 => $pos->{$b}{cx}, y2 => $pos->{$b}{cy},
                    stroke => $stroke, 'stroke-width' => 2,
                    'stroke-opacity' => 0.7,
                });
            }
        });

        $self->_el($h, 'g', { class => 'edge-labels' }, sub {
            for my $e ($g->{edges}->@*) {
                my ($a, $b) = ($e->{a} // '', $e->{b} // '');
                next unless $pos->{$a} && $pos->{$b};
                my $cost = $e->{cost};
                next unless defined $cost && length $cost;
                my ($lx, $ly) = $self->edge_label_point($pos, $a, $b);
                $self->_el($h, 'text', {
                    x => $lx, y => $ly + 4, 'text-anchor' => 'middle',
                    fill => length($e->{color} // '') ? $e->{color} : '#64748b',
                    stroke => '#05080f', 'stroke-width' => 3,
                    'paint-order' => 'stroke',
                    'font-family' => FONT_MONO, 'font-size' => 11,
                }, sub { $self->_text($h, $cost) });
            }
        });

        for my $r ($regions->@*) {
            $self->_el($h, 'g', { class => 'region', 'data-id' => $r->{id} }, sub {
                $self->_el($h, 'rect', {
                    x => $r->{x}, y => $r->{y},
                    width => $r->{w}, height => $r->{h}, rx => 14,
                    fill => $r->{bg}, 'fill-opacity' => 0.85,
                    stroke => $r->{accent}, 'stroke-width' => 1.5,
                });
                $self->_el($h, 'text', {
                    x => $r->{x} + Amin::Map::Target::Base::REGION_PAD,
                    y => $r->{y} + 24,
                    fill => $r->{accent}, 'font-family' => FONT_MONO,
                    'font-size' => 12, 'letter-spacing' => 1.2,
                }, sub { $self->_text($h, uc $r->{id}) });

                for my $id ($r->{ids}->@*) {
                    my ($p, $n) = ($pos->{$id}, $g->{nodes}{$id});
                    my $status = $n->{status} // 'pending';
                    my $sc     = $self->status_color($status);
                    $self->_el($h, 'g', {
                        class => "node status-$status", 'data-id' => $id,
                    }, sub {
                        $self->_el($h, 'rect', {
                            x => $p->{x}, y => $p->{y},
                            width => $p->{w}, height => $p->{h}, rx => 10,
                            fill => '#111a2e', stroke => $sc, 'stroke-width' => 2,
                        });
                        $self->_el($h, 'circle', {
                            cx => $p->{x} + $p->{w} - 18,
                            cy => $p->{y} + 18, r => 5, fill => $sc,
                        });
                        $self->_el($h, 'text', {
                            x => $p->{x} + 14, y => $p->{y} + 28,
                            fill => '#e8f0ff', 'font-family' => FONT_MONO,
                            'font-size' => 13, 'font-weight' => 600,
                        }, sub { $self->_text($h, $id) });
                        if (length($n->{flavor} // '')) {
                            $self->_el($h, 'text', {
                                x => $p->{x} + 14, y => $p->{y} + 48,
                                fill => '#8ba3c7', 'font-family' => FONT_MONO,
                                'font-size' => 11,
                            }, sub { $self->_text($h, $n->{flavor}) });
                        }
                        if (length($n->{location} // '')) {
                            $self->_el($h, 'text', {
                                x => $p->{x} + 14, y => $p->{y} + 64,
                                fill => '#5f7699', 'font-family' => FONT_MONO,
                                'font-size' => 10,
                            }, sub { $self->_text($h, $n->{location}) });
                        }
                    });
                }
            });
        }
    });
    return;
}

1;
