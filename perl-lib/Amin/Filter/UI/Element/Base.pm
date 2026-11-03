package Amin::Filter::UI::Element::Base;

# ui: element  →  additive render fragment.  One filter per ui: kind
# (axa-plan §4.3): every kind owns a tiny Amin::Filter::UI::Element::* class,
# declared in machine_spec.xml as a `late`, element-scoped candidate bound to a
# `target` (ios / android / html).  The position's _LazyGate splices the filter
# in the moment its element's start_element flows through and un-splices it
# after the matching end_element — the profile itself is the switch.  No
# pre-scan, no DOM.
#
# The filter is ADDITIVE: it never consumes or rewrites the ui: element.  It
# prepends a synthetic sibling produced by the target and forwards <ui:X …>
# byte-for-byte.  What that sibling is depends on the dialect: a text target
# (SwiftUI / Compose) emits it as characters on an
# <amin:stream channel="ui-…"> element, while the event target (HTML) emits
# real html:* SAX events.  Either way the fragment is handed straight to this
# filter's own Handler, so it lands exactly where a sibling would.  A host with
# no ui: filters loaded (a tty/neutral host, or a machine upstream of the
# render host) therefore sees the whole ui: subtree pass through untouched, to
# be forwarded on in full to the next target with this machine's contribution
# added.
#
# The fragment comes from ONE shared render context per chain — an
# Amin::UI::Target::* instance injected as `Render`, chosen by the spec's
# <ui-dialect> entry for the effective target.  That target owns a bounded
# frame stack, so every ui: element nests correctly across the fleet while
# nothing retains a child subtree: open() at start, close() at end.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';
use Class::Tiny qw(Handler Log Mode Name Element Render);

our $UI_NS = 'http://projectamin.org/ns/ui/1';

# The ui: kind this filter projects.  Every concrete subclass states exactly one.
sub kind ($self) { die ref($self) . " must define kind()\n" }

sub _is_mine ($self, $e) {
    return 0 unless (($e->{NamespaceURI} // '') eq $UI_NS);
    return (($e->{LocalName} // '') eq $self->kind) ? 1 : 0;
}

# Attribute keys in Clark notation, exactly as the render target reads them —
# the raw SAX attribute hash carries LocalName/NamespaceURI, not the key form.
sub _clark ($m) {
    my %out;
    for my $k (keys %$m) {
        my $a = $m->{$k} // next;
        my $ln = $a->{LocalName} // '';
        next unless length $ln;
        my $ns = $a->{NamespaceURI} // '';
        $out{ length $ns ? "{$ns}$ln" : "{}${ln}" } = $a;
    }
    return \%out;
}

sub start_element ($self, $e) {
    # Additive prepend: this element's fragment goes BEFORE it.  The original
    # element is then forwarded verbatim (SUPER → Handler).
    if (my $r = $self->Render) {
        if (_is_mine($self, $e)) {
            $r->open($self->kind, _clark($e->{Attributes} // {}), $self->Handler);
        }
    }
    return $self->SUPER::start_element($e);
}

# Character data belongs to the innermost open ui: element.  The text event
# crosses every filter currently spliced (each shares the one render context),
# so only the filter whose kind is the target's current frame contributes it —
# the rest would duplicate it.  The original characters are still forwarded
# downstream unchanged (additive: nothing is consumed).
sub characters ($self, $c) {
    if (my $r = $self->Render) {
        my $tk = $r->top_kind;
        $r->text($c->{Data} // '') if defined $tk && $tk eq $self->kind;
    }
    return $self->SUPER::characters($c);
}

sub end_element ($self, $e) {
    my $r = $self->Render;
    my $mine = ($r && _is_mine($self, $e)) ? 1 : 0;
    my $ret = $self->SUPER::end_element($e);   # forward the original close first
    $r->close($self->kind, $self->Handler) if $mine;
    return $ret;
}

1;
