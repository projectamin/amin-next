package Amin::AI;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

# ═══════════════════════════════════════════════════════════════════════════
# Amin::AI — AI namespace: SAX filter base class + shared constants.
#
# Every Amin::AI::* filter (Gate, Inference, Embed, Memory, Graph, Provenance)
# is instantiated by the Dispatcher chain with Handler/Log/Mode/Name/Element
# and streams SAX events through it.  Constructors resolve to
# XML::SAX::Base::new (which blesses the args hash directly), while
# Class::Tiny generates the accessors.
#
# This base:
#   1. inherits XML::SAX::Base so unhandled events flow to $self->Handler;
#   2. declares the chain attrs plus capture state (_cap _buf _children _cur
#      _start_el);
#   3. captures the article element the filter is responsible for — the one
#      named by element() in the AI namespace — buffering direct child values
#      into _children;
#   4. calls on_article_close($start_el) when that element closes, where
#      subclasses do their work (emit ai:result, bc:object, ai:context, …);
#   5. provides the _attr / _child_vals / _emit_ai / provenance helpers the
#      AI subclasses share.
#
# Filters with element() → undef (Graph, Provenance) capture nothing and
# forward everything unless they override the SAX methods themselves.
# ═══════════════════════════════════════════════════════════════════════════

use parent 'XML::SAX::Base';
use parent 'Exporter';

use Class::Tiny qw(Handler Log Mode Name Element), {
    _cap      => 0,
    _buf      => '',
    _children => sub { +{} },
    _cur      => undef,
    _start_el => undef,
};

use constant AI_NS => 'http://projectamin.org/ns/ai/1';

our @EXPORT_OK   = qw(AI_NS);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

my $AI = AI_NS();

# ── helpers ─────────────────────────────────────────────────────────────
sub _is_ai ($e) { ($e->{NamespaceURI} // '') eq $AI }

sub _attr ($self, $e, $name) {
    return undef unless $e && $e->{Attributes};
    for my $k ("{}$name", "{{$AI}}$name") {
        return $e->{Attributes}{$k}{Value}
            if exists $e->{Attributes}{$k}
            && defined $e->{Attributes}{$k}{Value};
    }
    # convenience-only fallback: some callsites pass bare names like 'top-k'
    for my $k (keys %{$e->{Attributes}}) {
        next unless ref $e->{Attributes}{$k} eq 'HASH';
        return $e->{Attributes}{$k}{Value}
            if ($e->{Attributes}{$k}{LocalName} // '') eq $name;
    }
    return undef;
}

sub _child_vals ($self, $name) {
    return $self->{_children}{$name} // [];
}

sub _xmlns_ai_attr ($self) {
    return (
        '{}xmlns:ai' => {
            Name         => 'xmlns:ai',
            LocalName    => 'ai',
            Prefix       => 'xmlns',
            NamespaceURI => '',
            Value        => $AI,
        },
    );
}

# _provenance_attrs(tier => 0, model_id => 'amin-chat-7b') → sax attr list;
# attribute local names are literally like provenance.author_kind (TR-AI.1)
sub _provenance_attrs ($self, %o) {
    my $tier = $o{tier} // 0;
    my $fid  = $o{filter_id} // ref($self);
    my $ak   = 'ai';
    my %attrs;
    for my $pair ([author_kind => $ak], [filter_id => $fid], [tier => $tier]) {
        my ($ln, $v) = @$pair;
        $v = defined($v) ? "$v" : '';
        $attrs{"{}$ln"} = {
            Name         => "ai:provenance.$ln",
            LocalName    => "provenance.$ln",
            Prefix       => 'ai',
            NamespaceURI => $AI,
            Value        => $v,
        };
    }
    return %attrs;
}

# _emit_ai('result', kind => ..., rc => ..., …) emits one empty ai:<el> node
# with provenance + xmlns:ai attributes into the remaining chain.
sub _emit_ai ($self, $element, %vals) {
    my $h = $self->Handler or return;
    my %attrs = ($self->_provenance_attrs(tier => 0), $self->_xmlns_ai_attr);
    for my $k (keys %vals) {
        my $v = defined $vals{$k} ? "$vals{$k}" : '';
        $attrs{"{}$k"} = {
            Name         => "ai:$k",
            LocalName    => $k,
            Prefix       => 'ai',
            NamespaceURI => $AI,
            Value        => $v,
        };
    }
    $h->start_element({
        NamespaceURI => $AI, LocalName => $element,
        Name => "ai:$element", Prefix => 'ai', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $AI, LocalName => $element,
        Name => "ai:$element", Prefix => 'ai',
    });
    return;
}

# element() may be overridden by the subclass (Gate/Inference → 'request',
# Memory → 'query', Embed → 'embed'), or provided by the chain via the
# machine-spec Element attr; returns '' where this filter captures nothing.
sub _element_name ($self) {
    my $w = $self->element;
    return $w if defined $w && length $w;
    return $self->Element // '';
}

# ── SAX article capture ─────────────────────────────────────────────────

sub start_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if ($self->{_cap} && _is_ai($el)) {
        $self->{_cur} = $ln;
        $self->{_buf} = '';
    }
    elsif (_is_ai($el) && $ln eq ($self->_element_name // '')) {
        $self->{_cap}      = 1;
        $self->{_children} = {};
        $self->{_buf}      = '';
        $self->{_cur}      = undef;
        $self->{_start_el} = $el;
    }
    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) {
    $self->{_buf} .= $d->{Data} // '' if $self->{_cap};
    return $self->SUPER::characters($d);
}

sub end_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if ($self->{_cap} && _is_ai($el)) {
        if (defined $self->{_cur} && $self->{_cur} eq $ln) {
            my $t = $self->{_buf};
            $t =~ s/^\s+|\s+$//g;
            push $self->{_children}{$ln}->@*, $t;
            $self->{_cur} = undef;
            $self->{_buf} = '';
        }
        if (defined($self->element) && length($self->_element_name // '')
            && $ln eq $self->_element_name) {
            $self->{_cap} = 0;
            $self->on_article_close($self->{_start_el} // $el);
        }
    }
    return $self->SUPER::end_element($el);
}

sub on_article_close ($self, $el) { return; }

1;
