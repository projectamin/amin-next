package Amin::UI::Target::HTML;

# The HTML dialect of the ui: target contract (see Amin::UI::Target::Base).
# Selected by `--os=html`.  It is the one dialect whose fragments are NOT text:
# each verb writes real `html:*` SAX events in the XHTML namespace straight to
# the element filter's handler, and Amin::Handler::HTML serialises them with
# every attribute and text run escaped in one place.  So, unlike the source
# dialects, this target never builds markup from a string (axa-plan §4.5) and
# never touches Base's string buffer — it overrides the verbs outright.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UI::Target::Base';

use constant XHTML => 'http://www.w3.org/1999/xhtml';

# No fragments ride the stream: HTML is emitted as events.  Stated anyway so a
# reader sees the dialect's identity (and the target seam stays uniform).
sub channel ($self) { 'ui-html' }

# Container kinds → the tag they open, plus any static attributes.  `app` and
# `section` are handled separately (they carry a heading), and `navigate`,
# `image`, `asyncimage`, `searchable`, `form`, `select` and `cell` pull their
# attributes from the IR.
my %TAG = (
    scene   => ['main'],
    list    => ['ul'],
    row     => ['li'],
    item    => ['li'],
    column  => ['div', class => 'column'],
    hstack  => ['div', class => 'hstack'],
    vstack  => ['div', class => 'vstack'],
    stack   => ['div', class => 'stack'],
    grid    => ['div', class => 'grid'],
    card    => ['article'],
    button  => ['button'],
    toolbar => ['nav'],
    sheet   => ['dialog'],
    alert   => ['div', role => 'alert'],
    table   => ['table'],
    tr      => ['tr'],
);

# Leaf kinds → the tag whose content is the element's text.
my %LEAF = (
    text      => ['p'],
    label     => ['span', class => 'label'],
    badge     => ['span', class => 'badge'],
    progress  => ['progress'],
    sparkline => ['canvas', class => 'sparkline'],
    style     => ['style'],
);

# open: push a frame carrying the tags to close, then emit the opening events.
# A void element (img, input) closes itself and has no content.
sub open ($self, $k, $a, $h) {
    $a //= {};
    my $f = { kind => $k, text => '', closes => [], leaf => 0 };
    push @{ $self->stack }, $f;
    return $self unless $h;

    my $title = $self->attr($a, 'title');

    if ($k eq 'app') {
        $self->_start($h, 'html', lang => 'en');
        $self->_start($h, 'head');
        $self->_inline($h, 'title', $title);
        $self->_end($h, 'head');
        $self->_start($h, 'body');
        $f->{closes} = ['body', 'html'];
    }
    elsif ($k eq 'section') {
        $self->_start($h, 'section');
        $self->_inline($h, 'h2', $title);
        $f->{closes} = ['section'];
    }
    elsif ($k eq 'navigate') {
        $self->_start($h, 'a', href => $self->attr($a, 'to'));
        $self->_text($h, $title);          # the link label
        $f->{closes} = ['a'];
    }
    elsif ($k eq 'button') {
        $self->_start($h, 'button');
        $self->_text($h, $title);          # the button label
        $f->{closes} = ['button'];
    }
    elsif ($k eq 'image') {
        $self->_start($h, 'img', src => $title, alt => $title);
    }
    elsif ($k eq 'asyncimage') {
        my $url = $self->attr($a, 'url');
        $self->_start($h, 'img', src => $url, alt => '');
    }
    elsif ($k eq 'searchable') {
        $self->_start($h, 'input', type => 'search');
    }
    elsif ($k eq 'form') {
        my @at;
        push @at, method => $self->attr($a, 'method') if length $self->attr($a, 'method');
        push @at, action => $self->attr($a, 'action') if length $self->attr($a, 'action');
        $self->_start($h, 'form', @at);
        $f->{closes} = ['form'];
    }
    elsif ($k eq 'select') {
        my @at;
        push @at, name => $self->attr($a, 'name') if length $self->attr($a, 'name');
        $self->_start($h, 'select', @at);
        $f->{closes} = ['select'];
    }
    elsif ($k eq 'field') {
        # a void element: <input> closes itself and has no content
        my @at;
        my $type = $self->attr($a, 'type');
        push @at, type => (length $type ? $type : 'text');
        for my $n (qw(name value placeholder min max)) {
            my $v = $self->attr($a, $n);
            push @at, $n => $v if length $v;
        }
        $self->_start($h, 'input', @at);
    }
    elsif ($k eq 'option') {
        my @at;
        push @at, value => $self->attr($a, 'value') if length $self->attr($a, 'value');
        push @at, selected => 'selected'        if length $self->attr($a, 'selected');
        $self->_start($h, 'option', @at);
        $f->{closes} = ['option'];
        $f->{leaf}   = 1;
    }
    elsif ($k eq 'cell') {
        my $tag = length $self->attr($a, 'header') ? 'th' : 'td';
        $self->_start($h, $tag);
        $f->{closes} = [$tag];
    }
    elsif (my $t = $TAG{$k}) {
        $self->_start($h, $t->[0], @$t[1 .. $#$t]);
        $f->{closes} = [$t->[0]];
    }
    elsif (my $l = $LEAF{$k}) {
        $self->_start($h, $l->[0], @$l[1 .. $#$l]);
        $f->{closes} = [$l->[0]];
        $f->{leaf}   = 1;
    }
    # A cell (<td>/<th>) and an alert (<div role=alert>) hold their text inline:
    # like a leaf, that text is the element's sole content and is flushed on
    # close.  (Character data must be emitted at close — after the additive raw
    # ui: element's own close has been forwarded — or Handler::HTML, whose scope
    # top is then still the dropped ui: subtree, would discard it.)
    $f->{leaf} = 1 if $k eq 'cell' || $k eq 'alert';
    # an unknown kind emits nothing — the neutral Guard already dropped unknowns
    return $self;
}

# close: emit a leaf's accumulated text, then close the element's tags.  Only
# the frame stack is held, bounded by nesting depth — no subtree is retained.
sub close ($self, $k, $h) {
    my $f = pop @{ $self->stack } or return $self;
    return $self unless $h;
    $self->_text($h, $f->{text}) if $f->{leaf};
    $self->_end($h, $_) for reverse $f->{closes}->@*;
    return $self;
}

# ── XHTML event helpers (the twin of Amin::Example::Shop's _start/_end/_text) ──
sub _start ($self, $h, $ln, @attrs) {
    my %a = @attrs;
    $h->start_element({
        NamespaceURI => XHTML, LocalName => $ln, Name => $ln, Prefix => '',
        Attributes => {
            map {; "{}$_" => { Name => $_, LocalName => $_, Prefix => '',
                               NamespaceURI => '', Value => "$a{$_}" } }
            keys %a
        },
    });
    return;
}

sub _end ($self, $h, $ln) {
    $h->end_element({ NamespaceURI => XHTML, LocalName => $ln, Name => $ln, Prefix => '' });
    return;
}

sub _text ($self, $h, $t) {
    $h->characters({ Data => "$t" }) if defined $t && length $t;
    return;
}

sub _inline ($self, $h, $ln, $t) {
    $self->_start($h, $ln);
    $self->_text($h, $t);
    $self->_end($h, $ln);
    return;
}

1;
