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
use Amin::UI::Target::HTML::Theme;
use Amin::UI::Target::HTML::Player;
use Amin::UI::Target::HTML::Visualizer;

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
    markdown  => ['div', class => 'md', 'data-axa-md' => '1'],
    label     => ['span', class => 'label'],
    badge     => ['span', class => 'badge'],
    progress  => ['progress'],
    sparkline => ['canvas', class => 'sparkline'],
    style     => ['style'],
);

# Client half of ui:swap and ui:markdown.  A streamed document is parsed chunk
# by chunk, and HTML can only append: an element that already left the socket
# cannot be revised by markup alone.  The target therefore renders each ui:swap
# as an inert <template data-axa-swap="ID" data-axa-mode="…">.  The parser can
# pause inside that template, so a swap is applied only once the parser has
# moved on (a sibling appeared): at that point its content is complete.  A sweep
# on DOMContentLoaded/load covers the last one.  The same runtime renders
# ui:markdown leaves (data-axa-md) and serves the md / md-append swap modes, so
# a streaming source can be re-rendered in place as its blocks complete.
my $SWAP_RUNTIME = <<'JS';
(function(){
function tx(c){
var t;
if(c.children.length===1){
if(c.firstElementChild.children.length===0){t=c.firstElementChild.textContent}
}
if(t==null)t=c.textContent;
if(t.charAt(0)==='\n')t=t.slice(1);
return t
}
function mk(t,g){var e=document.createElement(t);if(g)e.className=g;return e}
function fill(el,ns){for(var i=0;ns.length>i;i++)el.appendChild(ns[i]);return el}
function inl(s){
var out=[],i=0,n=s.length;
while(n>i){
var r=s.slice(i),m,el,run;
m=/^`([^`]+)`/.exec(r);
if(m){el=mk('code');el.textContent=m[1];out.push(el);i+=m[0].length;continue}
m=/^\*\*([^*]+)\*\*/.exec(r);
if(!m)m=/^__([^_]+)__/.exec(r);
if(m){el=mk('strong');fill(el,inl(m[1]));out.push(el);i+=m[0].length;continue}
m=/^\*([^*\s][^*]*)\*/.exec(r);
if(!m)m=/^_([^_\s][^_]*)_/.exec(r);
if(m){el=mk('em');fill(el,inl(m[1]));out.push(el);i+=m[0].length;continue}
m=/^\[([^\]]+)\]\(([^)\s]+)\)/.exec(r);
if(m){
if(/^(https?:\/\/|mailto:|\/)/.test(m[2])){
el=mk('a');el.setAttribute('href',m[2]);el.setAttribute('rel','noreferrer noopener');el.setAttribute('target','_blank');fill(el,inl(m[1]));out.push(el);i+=m[0].length;continue
}
}
m=/^[^`*_\[]+/.exec(r);
run=m?m[0]:'';
if(run.length){
var last=out.length?out[out.length-1]:null;
if(!last){out.push(document.createTextNode(run))}
else if(last.nodeType===3){last.nodeValue+=run}
else{out.push(document.createTextNode(run))}
i+=run.length;continue}
out.push(document.createTextNode(r.charAt(0)));i++;
}
return out
}
function mdb(src){
var f=document.createDocumentFragment(),ls=src.split(/\r?\n/),i=0,n=ls.length,m;
function blank(s){return /^\s*$/.test(s)}
function take(dst,g){while(g.firstChild)dst.appendChild(g.firstChild);return dst}
while(n>i){
var ln=ls[i];
if(blank(ln)){i++;continue}
m=/^\s{0,3}(```+|~~~+)\s*([\w+.-]*)\s*$/.exec(ln);
if(m){
var buf=[],j=i+1;
while(n>j){if(/^\s{0,3}(```+|~~~+)\s*$/.test(ls[j]))break;buf.push(ls[j]);j++}
if(n>j)j++;
var pre=mk('pre'),co=mk('code');
if(m[2])co.className='lang-'+m[2];
co.textContent=buf.join('\n');pre.appendChild(co);f.appendChild(pre);i=j;continue}
if(/^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$/.test(ln)){f.appendChild(mk('hr'));i++;continue}
m=/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/.exec(ln);
if(m){f.appendChild(fill(mk('h'+m[1].length),inl(m[2])));i++;continue}
if(/^\s{0,3}>/.test(ln)){
var bq=mk('blockquote'),q=[];
while(n>i){
if(!/^\s{0,3}>/.test(ls[i]))break;
q.push(ls[i].replace(/^\s{0,3}> ?/,''));i++
}
f.appendChild(take(bq,mdb(q.join('\n'))));continue}
m=/^\s{0,3}[-*+]\s+(.*)$/.exec(ln);
if(m){
var ul=mk('ul');
while(n>i){
m=/^\s{0,3}[-*+]\s+(.*)$/.exec(ls[i]);
if(!m)break;
ul.appendChild(fill(mk('li'),inl(m[1])));i++
}
f.appendChild(ul);continue}
m=/^\s{0,3}\d+[.)]\s+(.*)$/.exec(ln);
if(m){
var ol=mk('ol');
while(n>i){
m=/^\s{0,3}\d+[.)]\s+(.*)$/.exec(ls[i]);
if(!m)break;
ol.appendChild(fill(mk('li'),inl(m[1])));i++
}
f.appendChild(ol);continue}
var parts=[];
while(n>i){
var lp=ls[i];
if(blank(lp))break;
if(/^\s{0,3}(#{1,6}\s|>|```|~~~|[-*+]\s|\d+[.)]\s)/.test(lp))break;
if(/^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$/.test(lp))break;
parts.push(lp.replace(/^\s+/,''));i++
}
if(parts.length){f.appendChild(fill(mk('p'),inl(parts.join(' '))))}
else{f.appendChild(fill(mk('p'),inl(ln)));i++}
}
return f
}
function mdRun(el){
var src=el._axaMd==null?'':el._axaMd;
while(el.firstChild)el.removeChild(el.firstChild);
el.appendChild(mdb(src))
}
function md1(el){
if(el.getAttribute('data-axa-md')!=='1')return;
el.setAttribute('data-axa-md','2');
el._axaMd=el.textContent;
mdRun(el)
}
function mdScan(n){
if(!n)return;
if(n.nodeType!==1)return;
md1(n);
if(n.querySelectorAll)Array.prototype.forEach.call(n.querySelectorAll('[data-axa-md="1"]'),md1)
}
function ap(t){
if(t.getAttribute('data-axa-done'))return;
var id=t.getAttribute('data-axa-swap'),el=id?document.getElementById(id):null;
if(!el)return;
t.setAttribute('data-axa-done','1');
var m=t.getAttribute('data-axa-mode')||'replace',c=t.content;
if(m==='text'){el.textContent=tx(c)}
else if(m==='md'){el.setAttribute('data-axa-md','2');el._axaMd=tx(c);mdRun(el)}
else if(m==='md-append'){el.setAttribute('data-axa-md','2');el._axaMd=(el._axaMd==null?'':el._axaMd)+tx(c);mdRun(el)}
else if(m==='text-append'){el.appendChild(document.createTextNode(tx(c)))}
else if(m==='append'){el.appendChild(c.cloneNode(true))}
else if(m==='prepend'){el.insertBefore(c.cloneNode(true),el.firstChild)}
else if(el.parentNode){el.parentNode.replaceChild(c.cloneNode(true),el)}
if(t.parentNode)t.parentNode.removeChild(t);
if(m==='append'||m==='prepend'||m==='text-append'||m==='md-append'){
if(el.scrollIntoView)el.scrollIntoView({block:'nearest'})
}
}
function sc(n){
mdScan(n);
var p=n.previousSibling;
if(!p)return;
if(p.nodeType!==1)return;
if(p.tagName!=='TEMPLATE')return;
if(p.getAttribute('data-axa-swap')!==null)ap(p)
}
function sw(){
Array.prototype.forEach.call(document.querySelectorAll('template[data-axa-swap]'),ap);
Array.prototype.forEach.call(document.querySelectorAll('[data-axa-md="1"]'),md1)
}
new MutationObserver(function(ms){
Array.prototype.forEach.call(ms,function(m){
Array.prototype.forEach.call(m.addedNodes,sc)
})
}).observe(document.documentElement,{childList:true,subtree:true});
if(document.readyState==='loading'){
document.addEventListener('DOMContentLoaded',sw)
}else{sw()}
window.addEventListener('load',sw);
})();
JS

# The generic id attribute: any ui: element can be addressed by later
# fragments (a swap target, an anchor), so its id rides through the same
# escaping as every other attribute.
sub _id ($self, $id) { length($id // '') ? (id => $id) : () }

# open: push a frame carrying the tags to close, then emit the opening events.
# A void element (img, input) closes itself and has no content.
sub open ($self, $k, $a, $h) {
    $a //= {};
    my $f = { kind => $k, text => '', closes => [], leaf => 0 };
    push @{ $self->stack }, $f;
    return $self unless $h;

    my $title = $self->attr($a, 'title');
    my @id    = $self->_id($self->attr($a, 'id'));

    if ($k eq 'swap') {
        my $for  = $self->attr($a, 'for');
        my $mode = $self->attr($a, 'mode');
        $mode = 'replace' unless length $mode;
        unless ($self->{_swap_runtime}) {
            $self->{_swap_runtime} = 1;
            $self->_inline($h, 'script', $SWAP_RUNTIME);
        }
        $self->_start($h, 'template',
            'data-axa-swap' => $for, 'data-axa-mode' => $mode);
        $f->{closes} = ['template'];
    }
    elsif ($k eq 'app') {
        $self->_start($h, 'html', lang => 'en');
        $self->_start($h, 'head');
        $self->_inline($h, 'title', $title);
        $self->_start($h, 'meta', name => 'viewport', content => 'width=device-width,initial-scale=1');
        $self->_end($h, 'meta');
        # The theme named by ui:app (default look when absent or unknown); zero
        # specificity, so an app's ui:style still wins.
        $self->_inline($h, 'style', Amin::UI::Target::HTML::Theme->css($self->attr($a, 'theme')));
        $self->_end($h, 'head');
        $self->_start($h, 'body');
        $f->{closes} = ['body', 'html'];
    }
    elsif ($k eq 'section') {
        $self->_start($h, 'section', @id);
        $self->_inline($h, 'h2', $title);
        $f->{closes} = ['section'];
    }
    elsif ($k eq 'navigate') {
        $self->_start($h, 'a', href => $self->attr($a, 'to'), @id);
        $self->_text($h, $title);          # the link label
        $f->{closes} = ['a'];
    }
    elsif ($k eq 'button') {
        $self->_start($h, 'button', @id);
        $self->_text($h, $title);          # the button label
        $f->{closes} = ['button'];
    }
    elsif ($k eq 'image') {
        $self->_start($h, 'img', src => $title, alt => $title, @id);
    }
    elsif ($k eq 'asyncimage') {
        my $url = $self->attr($a, 'url');
        $self->_start($h, 'img', src => $url, alt => '', @id);
    }
    elsif ($k eq 'audio') {
        # A transport element, not a leaf: the browser owns play transport,
        # so the element carries its source and stays open for fallback text.
        my $src = $self->attr($a, 'src');
        $src = $title unless length $src;
        my @at = (src => $src, controls => 'controls', preload => 'metadata');
        push @at, loop => 'loop' if length $self->attr($a, 'loop');
        $self->_start($h, 'audio', @at, @id);
        $f->{closes} = ['audio'];
    }
    elsif ($k eq 'player') {
        # The neutral AV container.  The target owns the client runtime, so an
        # app emits IR only; the script is emitted once, before the first
        # player, and binds every [data-axa-player] figure (including ones a
        # later ui:swap inserts).
        unless ($self->{_player_runtime}) {
            $self->{_player_runtime} = 1;
            $self->_inline($h, 'script', $Amin::UI::Target::HTML::Player::RUNTIME);
        }
        my @at = (class => 'player', 'data-axa-player' => '1');
        push @at, 'aria-label' => $title if length $title;
        $self->_start($h, 'figure', @at, @id);
        $f->{closes} = ['figure'];
    }
    elsif ($k eq 'equalizer') {
        # A leaf: an empty canvas the player runtime paints from the analyser
        # of the transport it sits beside.  No content, no fallback text.
        $self->_start($h, 'canvas',
            'data-axa-eq'   => '1',
            'data-bars'     => $self->eq_bars($a),
            'data-mode'     => $self->eq_mode($a),
            'aria-hidden'   => 'true', @id);
        $f->{closes} = ['canvas'];
        $f->{leaf}   = 1;
    }
    elsif ($k eq 'visualizer') {
        # The target owns the shader: the app names a curated mode only.  The
        # program rides once per page as a non-executable base64 payload (raw
        # GLSL could carry '<'), followed by the runtime that paints every
        # [data-axa-vis] canvas — including ones a later swap inserts — through
        # one pooled WebGL context.
        unless ($self->{_vis_runtime}) {
            $self->{_vis_runtime} = 1;
            $self->_start($h, 'script',
                type => 'application/octet-stream', 'data-axa-vis-shader' => '1');
            $self->_text($h, $Amin::UI::Target::HTML::Visualizer::SHADER);
            $self->_end($h, 'script');
            $self->_inline($h, 'script', $Amin::UI::Target::HTML::Visualizer::RUNTIME);
        }
        $self->_start($h, 'canvas',
            class         => 'vis',
            'data-axa-vis' => '1',
            'data-mode'   => $self->vis_mode($a),
            'aria-hidden' => 'true', @id);
        $f->{closes} = ['canvas'];
        $f->{leaf}   = 1;
    }
    elsif ($k eq 'searchable') {
        $self->_start($h, 'input', type => 'search', @id);
    }
    elsif ($k eq 'form') {
        my @at;
        push @at, method => $self->attr($a, 'method') if length $self->attr($a, 'method');
        push @at, action => $self->attr($a, 'action') if length $self->attr($a, 'action');
        $self->_start($h, 'form', @at, @id);
        $f->{closes} = ['form'];
    }
    elsif ($k eq 'select') {
        my @at;
        push @at, name => $self->attr($a, 'name') if length $self->attr($a, 'name');
        $self->_start($h, 'select', @at, @id);
        $f->{closes} = ['select'];
    }
    elsif ($k eq 'field' && $self->attr($a, 'type') eq 'multiline') {
        # a multi-line field: the value is the textarea's content
        my @at;
        for my $n (qw(name placeholder)) {
            my $v = $self->attr($a, $n);
            push @at, $n => $v if length $v;
        }
        my $rows = $self->attr($a, 'lines');
        push @at, rows => ($rows =~ /\A\d{1,2}\z/ && $rows > 0 ? $rows : 4);
        $self->_start($h, 'textarea', @at, @id);
        $f->{closes} = ['textarea'];
        $f->{text}   = $self->attr($a, 'value');
        $f->{leaf}   = 1;
    }
    elsif ($k eq 'field') {
        # a void element: <input> closes itself and has no content
        my @at;
        # semantic types (see Target::Base::field_type) → <input type>
        my $type = $self->attr($a, 'type');
        $type = 'password' if $type eq 'secure';
        $type = 'checkbox' if $type eq 'toggle';
        push @at, type => (length $type ? $type : 'text');
        for my $n (qw(name value placeholder min max)) {
            my $v = $self->attr($a, $n);
            push @at, $n => $v if length $v;
        }
        $self->_start($h, 'input', @at, @id);
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
        $self->_start($h, $tag, @id);
        $f->{closes} = [$tag];
    }
    elsif (my $t = $TAG{$k}) {
        $self->_start($h, $t->[0], @$t[1 .. $#$t], @id);
        $f->{closes} = [$t->[0]];
    }
    elsif (my $l = $LEAF{$k}) {
        # markdown is rendered by the same client runtime as ui:swap, so the
        # page carries it even when no swap fragment is present.
        if ($k eq 'markdown' && !$self->{_swap_runtime}) {
            $self->{_swap_runtime} = 1;
            $self->_inline($h, 'script', $SWAP_RUNTIME);
        }
        $self->_start($h, $l->[0], @$l[1 .. $#$l], @id);
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
