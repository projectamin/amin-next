package Amin::UI::Target::Base;

# ui: canonical IR  →  one target dialect (SwiftUI / Compose / HTML).
#
# The streaming contract (axa-plan §4.3, "no DOM anywhere"): a target is driven
# one element at a time — open(), then text() and any nested open…close, then
# close() — and writes each fragment straight to its sink.  A target never
# holds a child subtree across that child's close.  The only state it keeps is
# the frame stack: one small record per currently-open element (its pad, verb
# flags and accumulated leaf text), bounded by the nesting depth rather than by
# the size of the subtree.
#
# Subclasses supply the two dialect hooks and nothing else:
#
#   _cont($k,$pad,$pad1,$attrs) → { head, first, close_had, close_empty, post }
#                                 for a container kind, or undef for a leaf
#   _leaf($k,$pad,$attrs,$text) → the whole expression for a leaf kind
#
# Base owns the sink, the frame stack, the separator bookkeeping, and the
# identifier / string-literal folding that all source targets share.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use Class::Tiny { sink => undef, buf => '' }, { stack => sub { [] } };

# Synthetic-sibling wrapper for a text dialect's fragment (the sec: convention):
# the fragment rides as characters on an <amin:stream channel="…"> element so a
# downstream target can pick its projection out of the stream by channel.
use constant AMIN_NS => 'http://projectamin.org/ns/2026/';

# The 24 container kinds.  Every other kind in the 38-element ui: vocabulary is
# a leaf whose whole expression is produced on close().
our %CONTAINER = map {; $_ => 1 } qw(
    app scene list row column hstack vstack stack grid section card
    button navigate toolbar sheet alert item swap player
    form select table tr cell
);

sub is_container ($self, $k) { $CONTAINER{$k} ? 1 : 0 }

# The semantic ui:field types.  A target maps each to its own control; an
# unlisted type is plain text.  `hidden` carries a value with the enclosing
# form and draws nothing.
#   text  secure  toggle  number  multiline (lines=N)  hidden
sub field_type ($self, $a) {
    my $t = $self->attr($a, 'type');
    return $t =~ /\A(?:secure|toggle|number|multiline|hidden)\z/ ? $t : 'text';
}

# a toggle's value: anything but empty, 0, false or off
sub truthy ($self, $v) { return (length($v // '') && $v !~ /\A(?:0|false|off|no)\z/i) ? 1 : 0 }

# The wire channel this dialect publishes its fragments on.  Owned here so no
# element filter has to know which dialect it is serving.
sub channel ($self) { '' }

# Three sinks, in precedence order — same shape as Amin::Handler::HTML:
#   sink — coderef, called per fragment.  Streaming: O(1) memory.
#   buf  — accumulate; output() returns the whole projection.
sub emit ($self, $s) {
    if (my $sink = $self->sink) { $sink->($s); return $self }
    $self->buf($self->buf . $s);
    return $self;
}
sub output ($self) { $self->buf }

# Drain the fragments one verb produced.  The element-filter fleet shares ONE
# target instance per chain (bounded frame stack, injected as `Render`), so
# each filter calls open()/close() and then takes exactly that verb's fragment,
# keeping every fragment next to the element it came from, in stream order.
sub take ($self) { my $frag = $self->buf; $self->buf(''); return $frag }

# The kind of the innermost open element (the top frame), or undef when nothing
# is open.  Several fleet filters share this one target, so character data —
# which crosses every filter currently in the chain — must be contributed
# exactly once: only the filter whose kind is the current frame owns its text.
sub top_kind ($self) {
    my $f = $self->stack->[-1];
    return $f ? $f->{kind} : undef;
}

sub ind ($self, $n) { '    ' x $n }

# ── the streaming verbs ────────────────────────────────────────────────────
# open: emit the parent's separator, then this element's head, and push a
# frame.  close: pop the frame and emit its tail (a container's block close or
# a leaf's whole expression).  Each verb ends by handing the fragment it
# produced to the caller's downstream handler ($h) — the element filter passes
# its own Handler, so a fragment lands exactly where a synthetic sibling would.
sub open ($self, $k, $a, $h) {
    my $st  = $self->stack;
    my $pad = $self->ind(scalar $st->@*);

    # Tell the parent a child has started.  A lazy container opens its body
    # here (its head only carried the expression up to the block); an eager
    # one has already opened the body and only needs a line break.
    if (my $p = $st->[-1]) {
        $self->emit($p->{had} ? "\n" : ($p->{first} // ''));
        $p->{had} = 1;
    }

    my $attrs = $a // {};
    my $f = { kind => $k, pad => $pad, attrs => $attrs, text => '', had => 0 };
    if (my $c = $self->_cont($k, $pad, $self->ind(scalar($st->@*) + 1), $attrs)) {
        $f->{container}   = 1;
        $f->{first}       = $c->{first}       // " {\n";
        $f->{close_had}   = $c->{close_had}   // "\n$pad}";
        $f->{close_empty} = $c->{close_empty} // " { }";
        $f->{post}        = $c->{post};
        $self->emit($c->{head});
    }
    push @$st, $f;
    $self->_deliver($h);
    return $self;
}

sub text ($self, $t) {
    my $f = $self->stack->[-1] or return $self;
    $f->{text} .= $t // '';
    return $self;
}

sub close ($self, $k, $h) {
    my $f = pop @{ $self->stack };
    if ($f->{container}) {
        $self->emit($f->{had} ? $f->{close_had} : $f->{close_empty});
        $self->emit($f->{post}) if defined $f->{post} && length $f->{post};
    } else {
        $self->emit($self->_leaf($k, $f->{pad}, $f->{attrs}, $f->{text}));
    }
    $self->_deliver($h);
    return $self;
}

# Hand the fragment the last verb produced to the downstream handler.  A text
# dialect's fragment is characters, so wrap it in an amin:stream sibling tagged
# with this dialect's channel.  An event dialect (HTML) overrides the verbs
# themselves: its fragments are already real events and never come from a
# string (§4.5).
sub _deliver ($self, $h) {
    my $text = $self->take;
    return unless defined $text && length $text;
    return unless $h;
    my $ns = AMIN_NS;
    my $ch = $self->channel;
    $h->start_element({
        NamespaceURI => $ns, LocalName => 'stream',
        Name => 'amin:stream', Prefix => 'amin',
        Attributes => { "{$ns}channel" => {
            Name => 'amin:channel', LocalName => 'channel', Prefix => 'amin',
            NamespaceURI => $ns, Value => $ch } },
    });
    $h->characters({ Data => $text });
    $h->end_element({
        NamespaceURI => $ns, LocalName => 'stream',
        Name => 'amin:stream', Prefix => 'amin',
    });
    return;
}

# ── shared IR accessors / folding ──────────────────────────────────────────
# A `ui:` attribute value (unnamespaced; the closed-view vocab has fifteen:
# title spacing points for-each bind url action method min max placeholder
# selected header bars mode) or '' when absent.  Attribute keys are Clark
# notation, exactly as the canonical IR carries them.
sub attr ($self, $a, $name) {
    my $x = $a->{"{}${name}"} // return '';
    return $x->{Value} // '';
}

# A target-language identifier from a free-form ui: title — `title` is
# authored text ("Amin Fabric — Shop"), not a symbol, so every source target
# folds it to a legal type / function name.
sub ident ($self, $s) {
    my @w = grep { length } split /[^A-Za-z0-9]+/, (defined $s ? $s : '');
    return 'Root' unless @w;
    my $id = join '', map { ucfirst lc $_ } @w;
    $id = "N$id" if $id =~ /^[0-9]/;
    return $id;
}

# A quoted literal.  Swift and Kotlin share these escape rules for everything
# the ui: vocabulary can carry in text and attribute values.
sub lit ($self, $s) {
    my $t = $s // '';
    $t =~ s/\\/\\\\/g;
    $t =~ s/"/\\"/g;
    $t =~ s/\n/\\n/g;
    $t =~ s/\r/\\r/g;
    return qq{"$t"};
}

# ui:equalizer shape, clamped to what every target can draw: 2..64 bars,
# `bars` or `wave`.  Owned here so the web runtime and the native projections
# cannot disagree about the shape the profile asked for.
sub eq_bars ($self, $a) {
    my $n = $self->attr($a, 'bars');
    return ($n =~ /\A\d{1,2}\z/ && $n >= 2 && $n <= 64) ? $n + 0 : 32;
}
sub eq_mode ($self, $a) {
    return $self->attr($a, 'mode') eq 'wave' ? 'wave' : 'bars';
}

1;
