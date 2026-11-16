package Amin::Content;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

# ═══════════════════════════════════════════════════════════════════════════
# Amin::Content — content/document filter base: platform-shipped document
# generation lives in the core `amin:` namespace.
#
# Every filter that ships as part of the Amin platform owns its XML vocabulary
# in the Amin namespace, so application (or Rust) filters can pick THEIR own
# namespace URIs without colliding with core semantics.  The document grammar
# is therefore `amin:document` / `amin:sheet` / `amin:cell`, not a generic
# `content:` prefix an app might also want to claim.
#
# Filters are instantiated by the Dispatcher's lazy gate with
# Handler/Log/Mode/Name/Element, capture the grammar they own, and emit
# amin:result plus one compact bc:object artifact reference.
#
# This base provides the namespace binding, attribute lookup, result/bc event
# emitters and the shared CAS path.  The document grammar itself lives in
# Amin::Content::Document; format writers live behind
# Amin::Content::Format::Registry.
# ═══════════════════════════════════════════════════════════════════════════

use parent 'XML::SAX::Base';
use parent 'Exporter';

use Amin qw(NS);

use Class::Tiny qw(Handler Log Mode Name Element), {
    _cap => 0,
};

use constant BC_NS => 'http://projectamin.org/ns/bc/';

our @EXPORT_OK   = qw(BC_NS);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

my $AMIN = NS();
my $BC   = BC_NS();

sub _is_content ($e) {
    return ($e->{NamespaceURI} // '') eq $AMIN;
}

# element() may be provided by the subclass or by the chain via the
# machine-spec Element attr; both name the one content: element this filter
# owns.  '' means it owns no single element.
sub _element_name ($self) {
    my $w = $self->element;
    return $w if defined $w && length $w;
    return $self->Element // '';
}

sub _attr ($self, $e, $name) {
    return undef unless $e && ref($e->{Attributes}) eq 'HASH';
    for my $k ("{$AMIN}$name", "{}name") {
        return $e->{Attributes}{$k}{Value}
            if exists $e->{Attributes}{$k}
            && defined $e->{Attributes}{$k}{Value};
    }
    for my $k (keys %{$e->{Attributes}}) {
        next unless ref $e->{Attributes}{$k} eq 'HASH';
        return $e->{Attributes}{$k}{Value}
            if ($e->{Attributes}{$k}{LocalName} // '') eq $name;
    }
    return undef;
}

sub _xmlns_bc_attr ($self) {
    return (
        '{}xmlns:bc' => {
            Name         => 'xmlns:bc',
            LocalName    => 'bc',
            Prefix       => 'xmlns',
            NamespaceURI => '',
            Value        => $BC,
        },
    );
}

sub _content_attrs ($self, %vals) {
    my %attrs;
    for my $k (keys %vals) {
        my $v = defined $vals{$k} ? "$vals{$k}" : '';
        $attrs{"{$AMIN}$k"} = {
            Name         => "amin:$k",
            LocalName    => $k,
            Prefix       => 'amin',
            NamespaceURI => $AMIN,
            Value        => $v,
        };
    }
    return %attrs;
}

sub _emit_content ($self, $element, %vals) {
    my $h = $self->Handler or return;
    my %attrs = $self->_content_attrs(%vals);
    $h->start_element({
        NamespaceURI => $AMIN, LocalName => $element,
        Name => "amin:$element", Prefix => 'amin', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $AMIN, LocalName => $element,
        Name => "amin:$element", Prefix => 'amin',
    });
    return;
}

sub _emit_result ($self, %vals) {
    return $self->_emit_content('result', %vals);
}

sub _emit_bc_object ($self, %attrs) {
    my $h = $self->Handler or return;
    my %a = ($self->_xmlns_bc_attr);
    for my $k (keys %attrs) {
        my $v = defined $attrs{$k} ? "$attrs{$k}" : '';
        $a{"{$BC}$k"} = {
            Name         => "bc:$k",
            LocalName    => $k,
            Prefix       => 'bc',
            NamespaceURI => $BC,
            Value        => $v,
        };
    }
    $h->start_element({
        NamespaceURI => $BC, LocalName => 'object',
        Name => 'bc:object', Prefix => 'bc', Attributes => \%a,
    });
    $h->end_element({
        NamespaceURI => $BC, LocalName => 'object',
        Name => 'bc:object', Prefix => 'bc',
    });
    return;
}

sub _bc_put ($self, $dataref) {
    require Amin::Artifact;
    return Amin::Artifact::bc_put($dataref);
}

1;
