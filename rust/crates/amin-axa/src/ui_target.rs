//! The `ui:` → `html:` projection — the Rust form of `Amin::UI::Target::HTML`.
//!
//! There is no closed-world kind list here: the render path is the *producer*
//! of `ui:` IR (its own app filter emits it), and the closed-world contract is
//! the machine spec's declared vocabulary — enforced in the chain by
//! `Amin::Filter::UI::Guard` and carried by `bsax::vocab::Vocab`.  Repeating the
//! kind set in this target only gave it a second place to drift.
//!
//! A target is driven one element at a time (axa-plan §4.3, "no DOM
//! anywhere"): [`HtmlTarget::open`] then nested opens/closes, then
//! [`HtmlTarget::close`]. It holds only a bounded frame stack — one small
//! record per currently-open element — never a child subtree. Where the
//! source dialects accumulate a string and hand it on, the HTML dialect emits
//! real `html:` XHTML events straight to the serializer, so markup is never
//! built from a string (§4.5) and every attribute and text run is escaped in
//! exactly one place.
//!
//! The projection tables, the per-kind open/close semantics (which kinds carry
//! a heading, which pull attributes from the IR, which flush their text on
//! close) and the `cell`→`th`/`td` and `field` void-`<input>` rules are the
//! Perl target's, verbatim, because the pages it produces must be identical.

use std::collections::HashMap;

use amin_sax::{Attributes, SaxError};

use crate::serializer::HtmlSerializer;

/// The HTML target's default look, emitted in `<head>` before any app CSS.
///
/// Verbatim from `Amin::UI::Target::HTML::Material::$CSS`: zero-specificity
/// `:where()` selectors and Material role variables, so an app's `ui:style`
/// still wins. Byte-identical CSS is part of the Perl/Rust page contract.
const MATERIAL_CSS: &str = r#":root{color-scheme:light dark;
--md-primary:#6750a4;--md-on-primary:#fff;--md-primary-container:#eaddff;--md-on-primary-container:#21005d;
--md-secondary-container:#e8def8;--md-on-secondary-container:#1d192b;
--md-background:#fef7ff;--md-on-background:#1d1b20;
--md-surface:#fef7ff;--md-on-surface:#1d1b20;--md-on-surface-variant:#49454f;
--md-surface-container:#f3edf7;--md-surface-container-high:#ece6f0;
--md-outline:#79747e;--md-outline-variant:#cac4d0;--md-error:#b3261e;
--md-radius-s:8px;--md-radius-m:12px;--md-radius-full:999px;
--md-font:Roboto,system-ui,-apple-system,'Segoe UI',sans-serif;
--md-mono:ui-monospace,'JetBrains Mono',Consolas,monospace}
@media (prefers-color-scheme:dark){:root{
--md-primary:#d0bcff;--md-on-primary:#381e72;--md-primary-container:#4f378b;--md-on-primary-container:#eaddff;
--md-secondary-container:#4a4458;--md-on-secondary-container:#e8def8;
--md-background:#141218;--md-on-background:#e6e0e9;
--md-surface:#141218;--md-on-surface:#e6e0e9;--md-on-surface-variant:#cac4d0;
--md-surface-container:#211f26;--md-surface-container-high:#2b2930;
--md-outline:#938f99;--md-outline-variant:#49454f;--md-error:#f2b8b5}}
:where(*){box-sizing:border-box}
:where(body){margin:0;background:var(--md-background);color:var(--md-on-background);font:14px/1.5 var(--md-font)}
:where(p){margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
:where(h2){margin:0;font:500 14px/1.4 var(--md-font);color:var(--md-on-surface-variant);letter-spacing:.01em}
:where(section){display:flex;flex-direction:column;gap:12px}
:where(a){color:var(--md-primary)}
:where(.hstack){display:flex;align-items:center;gap:8px;min-width:0}
:where(.vstack){display:flex;flex-direction:column;gap:6px;min-width:0}
:where(.column){display:flex;flex-direction:column;gap:12px;min-width:0}
:where(.stack){display:flex;min-width:0}
:where(.grid){display:grid;gap:8px}
:where(main){display:block;padding:16px;max-width:880px;margin:0 auto}
:where(main>.column){gap:16px}
:where(main:has(>.hstack)){max-width:1280px}
:where(main>.hstack){align-items:flex-start;gap:16px}
:where(main>.hstack>.column){flex:1 1 0;min-width:0}
@media (max-width:800px){:where(main>.hstack){flex-direction:column;align-items:stretch}}
:where(nav){display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:56px;padding:0 16px;background:var(--md-surface-container);color:var(--md-on-surface);border-bottom:1px solid var(--md-outline-variant)}
:where(nav form){flex-direction:row}
:where(article){display:flex;flex-direction:column;gap:12px;padding:16px;background:var(--md-surface-container);color:var(--md-on-surface);border-radius:var(--md-radius-m)}
:where(article article){background:var(--md-surface-container-high)}
:where(form){margin:0;display:flex;flex-direction:column;gap:12px}
:where(span.label){color:var(--md-on-surface-variant);font-size:12px;letter-spacing:.03em}
:where(span.badge){display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:20px;padding:0 8px;border-radius:var(--md-radius-s);background:var(--md-secondary-container);color:var(--md-on-secondary-container);font:500 12px/1 var(--md-font)}
:where(input,textarea,select){width:100%;padding:10px 12px;background:transparent;color:var(--md-on-surface);border:1px solid var(--md-outline);border-radius:var(--md-radius-s);font:inherit}
:where(textarea){resize:vertical;font-family:var(--md-mono);font-size:13px}
:where(input::placeholder,textarea::placeholder){color:var(--md-on-surface-variant);opacity:.7}
:where(input:focus,textarea:focus,select:focus){outline:2px solid var(--md-primary);outline-offset:-1px;border-color:var(--md-primary)}
:where(input[type=checkbox]){width:18px;height:18px;padding:0;accent-color:var(--md-primary)}
:where(input[type=number]){width:96px}
:where(button){padding:9px 20px;border:0;border-radius:var(--md-radius-full);background:var(--md-primary);color:var(--md-on-primary);font:500 14px var(--md-font);letter-spacing:.01em;cursor:pointer}
:where(button:hover){filter:brightness(1.08)}
:where(button:focus-visible){outline:2px solid var(--md-primary);outline-offset:2px}
:where(nav button,article>.hstack button){background:transparent;color:var(--md-primary);padding:6px 12px}
:where(nav button:hover,article>.hstack button:hover){background:var(--md-secondary-container);filter:none}
:where(audio){width:100%}
:where(figure.player){display:flex;flex-direction:column;gap:10px;margin:0;padding:12px 14px;background:var(--md-surface-container-high);border-radius:var(--md-radius-m)}
:where(figure.player audio){margin:0}
:where(figure.player canvas){display:block;width:100%;height:44px;--axa-eq:var(--md-primary)}
:where(progress){width:100%;accent-color:var(--md-primary)}
:where(div[role=alert]){padding:12px 16px;border-radius:var(--md-radius-s);background:var(--md-surface-container-high);color:var(--md-error);border:1px solid var(--md-error)}
:where(table){border-collapse:collapse;width:100%}
:where(th,td){padding:8px 12px;text-align:left;border-bottom:1px solid var(--md-outline-variant)}
:where(dialog){background:var(--md-surface-container-high);color:var(--md-on-surface);border:0;border-radius:28px;padding:24px}
:where(ul){margin:0;padding-left:20px}
"#;

/// Client half of `ui:player` / `ui:equalizer`, verbatim from
/// `Amin::UI::Target::HTML::Player::$RUNTIME`: the page bytes are part of the
/// Perl/Rust parity contract, so the script is copied, not re-authored.  It is
/// emitted once, before the first player; the runtime also binds players a
/// later swap inserts.
const PLAYER_RUNTIME: &str = r#"(function(){
var AC=window.AudioContext||window.webkitAudioContext;
var ctx=null,recs=[],loop=false;
function audioCtx(){
if(ctx)return ctx;
if(!AC)return null;
try{ctx=new AC()}catch(e){ctx=null}
return ctx
}
function css(el,p){return getComputedStyle(el).getPropertyValue(p).trim()}
function colour(el){
var v=css(el,'--axa-eq');
if(v)return v;
v=css(el,'--md-primary');
return v?v:'#6750a4'
}
function fit(cv){
var dpr=window.devicePixelRatio||1,w=cv.clientWidth||320,h=cv.clientHeight||44;
var W=Math.round(w*dpr),H=Math.round(h*dpr);
if(cv.width!==W)cv.width=W;
if(cv.height!==H)cv.height=H;
var g=cv.getContext('2d');
if(!g)return null;
g.setTransform(dpr,0,0,dpr,0,0);
return g
}
function barsOf(cv){
var n=parseInt(cv.getAttribute('data-bars'),10);
if(!(n>0))n=32;
if(n>64)n=64;
return n
}
function draw(cv,g,vals){
var w=cv.clientWidth||320,h=cv.clientHeight||44,n=barsOf(cv),mode=cv.getAttribute('data-mode');
g.clearRect(0,0,w,h);
g.fillStyle=colour(cv);
if(mode==='wave'){
g.strokeStyle=colour(cv);
g.lineWidth=2;
g.beginPath();
var i=0,step=w/(n>1?n-1:1),len=vals.length;
while(n>i){
var v=vals[Math.floor(i*len/n)]/128-1,y=h/2+v*h*0.42;
if(i===0)g.moveTo(0,y);else g.lineTo(i*step,y);
i++;
}
g.stroke();
return
}
var bw=Math.max(2,(w/n)*0.62),gap=(w-bw*n)/(n>1?n-1:1),i=0,len=vals.length;
while(n>i){
var mag=vals[Math.floor(i*len/n)]/255,bh=Math.max(2,h*mag);
g.fillRect(i*(bw+gap),h-bh,bw,bh);
i++;
}
}
function flat(cv,level){
var g=fit(cv);
if(!g)return;
var n=barsOf(cv),vals=new Uint8Array(n),i=0;
while(n>i){vals[i]=level;i++}
draw(cv,g,vals)
}
function idle(cv){flat(cv,96)}
function stopped(cv){flat(cv,34)}
function tick(){
var i=0,n=recs.length;
while(n>i){
var r=recs[i],g=fit(r.cv);
if(g){
if(r.au.paused){stopped(r.cv)}
else{
r.an.getByteFrequencyData(r.freq);
if(r.mode==='wave'){r.an.getByteTimeDomainData(r.buf);draw(r.cv,g,r.buf)}
else{draw(r.cv,g,r.freq)}
}
}
i++;
}
if(recs.length)requestAnimationFrame(tick);else loop=false
}
function reduced(){
return window.matchMedia?window.matchMedia('(prefers-reduced-motion: reduce)').matches:false
}
function bind(el){
if(!el||el.nodeType!==1)return;
if(el.getAttribute('data-axa-player')!=='1')return;
if(el.getAttribute('data-axa-player-ready')==='1')return;
el.setAttribute('data-axa-player-ready','1');
var au=el.querySelector('audio'),cv=el.querySelector('[data-axa-eq]');
if(!cv)return;
if(!au){idle(cv);return}
var c=audioCtx();
if(!c){idle(cv);return}
var an=au._axaAnalyser;
if(!an){
try{
var src=au._axaSource;
if(!src){src=c.createMediaElementSource(au);au._axaSource=src}
an=c.createAnalyser();
an.fftSize=128;
an.smoothingTimeConstant=0.82;
src.connect(an);
an.connect(c.destination);
au._axaAnalyser=an;
}catch(e){idle(cv);return}
}
au.addEventListener('play',function(){if(c.state==='suspended')c.resume()});
if(reduced()){
au.addEventListener('play',function(){stopped(cv)});
au.addEventListener('pause',function(){stopped(cv)});
idle(cv);
return
}
var rec={au:au,cv:cv,an:an,mode:(cv.getAttribute('data-mode')||'bars'),buf:new Uint8Array(an.fftSize),freq:new Uint8Array(an.frequencyBinCount)};
var i=0,have=false;
while(recs.length>i){if(recs[i].cv===cv)have=true;i++}
if(!have)recs.push(rec);
if(!loop){loop=true;requestAnimationFrame(tick)}
idle(cv)
}
function scan(n){
if(!n||n.nodeType!==1)return;
bind(n);
if(n.querySelectorAll)Array.prototype.forEach.call(n.querySelectorAll('[data-axa-player]'),bind)
}
function all(){
Array.prototype.forEach.call(document.querySelectorAll('[data-axa-player]'),bind)
}
new MutationObserver(function(ms){
Array.prototype.forEach.call(ms,function(m){
Array.prototype.forEach.call(m.addedNodes,scan)
})
}).observe(document.documentElement,{childList:true,subtree:true});
function unlock(){
var c=audioCtx();
if(c){if(c.state==='suspended')c.resume()}
document.removeEventListener('pointerdown',unlock);
document.removeEventListener('keydown',unlock)
}
document.addEventListener('pointerdown',unlock);
document.addEventListener('keydown',unlock);
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',all)}else{all()}
window.addEventListener('load',all);
window.addEventListener('resize',function(){
var i=0,n=recs.length;
while(n>i){if(recs[i].au.paused)stopped(recs[i].cv);i++}
});
})();
"#;

/// Client half of `ui:swap` / `ui:markdown`, verbatim from
/// `Amin::UI::Target::HTML::$SWAP_RUNTIME`: the page bytes are part of the
/// Perl/Rust parity contract.  A streamed page cannot revise an element that
/// already left the socket, so a swap rides out as an inert
/// `<template data-axa-swap=…>` that the runtime applies once its content is
/// complete; markdown leaves render in place from the same script.
const SWAP_RUNTIME: &str = r#"(function(){
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
"#;

/// A `ui:` element's attributes, keyed in Clark notation (`{uri}local`, or
/// `{}local` for an unprefixed attribute) — exactly the key form the Perl
/// target reads.
pub type Attrs = HashMap<String, String>;

/// Collect an [`Attributes`] view into a Clark-keyed [`Attrs`] map
/// (≈ `Amin::Filter::UI::Element::Base::_clark`).
#[must_use]
pub fn clark_attrs(atts: &dyn Attributes) -> Attrs {
    let mut map = Attrs::new();
    for i in 0..atts.length() {
        let local = atts.local_name(i);
        if local.is_empty() {
            continue;
        }
        let ns = atts.uri(i);
        let key = if ns.is_empty() {
            format!("{{}}{local}")
        } else {
            format!("{{{ns}}}{local}")
        };
        map.insert(key, atts.value(i).to_string());
    }
    map
}

/// An unprefixed `ui:` attribute value (`attr($a, $name)`), or `""`.
#[must_use]
pub fn attr<'a>(a: &'a Attrs, name: &str) -> &'a str {
    a.get(&format!("{{}}{name}")).map_or("", String::as_str)
}

/// An unprefixed `ui:` attribute value, or `None` when absent — the `//`
/// distinction the route selector needs.
#[must_use]
pub fn attr_opt<'a>(a: &'a Attrs, name: &str) -> Option<&'a str> {
    a.get(&format!("{{}}{name}")).map(String::as_str)
}

/// `ui:equalizer` shape — the same clamp as `Amin::UI::Target::Base::eq_bars`.
/// Perl matches `\A\d{1,2}\z` and 2..=64, so a sign, whitespace or a third digit
/// falls back to the default rather than parsing (`"+5"`, `"007"` are not 5/7).
fn eq_bars(a: &Attrs) -> u8 {
    let raw = attr(a, "bars");
    let digits = raw.bytes().all(|b| b.is_ascii_digit());
    match raw.parse::<u8>() {
        Ok(n) if digits && (1..=2).contains(&raw.len()) && (2..=64).contains(&n) => n,
        _ => 32,
    }
}

/// `ui:equalizer` mode — `wave` or `bars` (anything else is `bars`).
fn eq_mode(a: &Attrs) -> &str {
    if attr(a, "mode") == "wave" {
        "wave"
    } else {
        "bars"
    }
}

/// `ui:field type=multiline lines=N` — Perl keeps the raw string when it is
/// `\A\d{1,2}\z` and numerically positive, else the default row count.
fn textarea_rows(a: &Attrs) -> String {
    let raw = attr(a, "lines");
    let digits =
        (1..=2).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_digit());
    if digits && raw.parse::<u32>().unwrap_or(0) > 0 {
        raw.to_string()
    } else {
        "4".to_string()
    }
}

/// Append the generic `ui:id` to an element's attributes.
///
/// Any projected element can be addressed by later fragments (a swap target, an
/// anchor) and Perl's `_id` rides it through everywhere but `option`; matching
/// that keeps an id-bearing page byte-identical between the two targets.
fn with_id<'a>(mut at: Vec<(&'a str, &'a str)>, a: &'a Attrs) -> Vec<(&'a str, &'a str)> {
    let id = attr(a, "id");
    if !id.is_empty() {
        at.push(("id", id));
    }
    at
}

/// A sink for canonical `ui:` IR events. The app filter emits into this; the
/// render pipeline ([`crate::render::Renderer`]) implements it to drive the
/// projection and the serializer.
pub trait UiSink {
    /// Open a `ui:` container/leaf element.
    fn start(&mut self, kind: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError>;
    /// Emit character data belonging to the innermost open element.
    fn text(&mut self, text: &str) -> Result<(), SaxError>;
    /// Close the innermost open `ui:` element.
    fn end(&mut self, kind: &str) -> Result<(), SaxError>;
    /// Open and immediately close a `ui:` element (a void one, e.g. `ui:field`).
    fn void(&mut self, kind: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError> {
        self.start(kind, attrs)?;
        self.end(kind)
    }
}

/// The HTML dialect: one frame per open `ui:` element, each recording the
/// XHTML tags to close and whether its text is flushed on close.
#[derive(Debug, Default)]
pub struct HtmlTarget {
    stack: Vec<Frame>,
    /// The player runtime has been emitted (once per page, like the Perl target).
    player_runtime: bool,
    /// The swap/markdown runtime has been emitted (once per page; Perl's
    /// `_swap_runtime`, shared by `ui:swap` and `ui:markdown`).
    swap_runtime: bool,
}

#[derive(Debug)]
struct Frame {
    kind: String,
    text: String,
    closes: Vec<String>,
    leaf: bool,
}

/// Container kinds → `(tag, static attributes)` — `%TAG`, verbatim.
fn static_tag(kind: &str) -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
    Some(match kind {
        "scene" => ("main", &[]),
        "list" => ("ul", &[]),
        "row" => ("li", &[]),
        "item" => ("li", &[]),
        "column" => ("div", &[("class", "column")]),
        "hstack" => ("div", &[("class", "hstack")]),
        "vstack" => ("div", &[("class", "vstack")]),
        "stack" => ("div", &[("class", "stack")]),
        "grid" => ("div", &[("class", "grid")]),
        "card" => ("article", &[]),
        "button" => ("button", &[]),
        "toolbar" => ("nav", &[]),
        "sheet" => ("dialog", &[]),
        "alert" => ("div", &[("role", "alert")]),
        "table" => ("table", &[]),
        "tr" => ("tr", &[]),
        _ => return None,
    })
}

/// Leaf kinds → `(tag, static attributes)` — `%LEAF`, verbatim.
fn static_leaf(kind: &str) -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
    Some(match kind {
        "text" => ("p", &[]),
        "markdown" => ("div", &[("class", "md"), ("data-axa-md", "1")]),
        "label" => ("span", &[("class", "label")]),
        "badge" => ("span", &[("class", "badge")]),
        "progress" => ("progress", &[]),
        "sparkline" => ("canvas", &[("class", "sparkline")]),
        "style" => ("style", &[]),
        _ => return None,
    })
}

impl HtmlTarget {
    /// A fresh target with an empty frame stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The kind of the innermost open element, or `None`.
    #[must_use]
    pub fn top_kind(&self) -> Option<&str> {
        self.stack.last().map(|f| f.kind.as_str())
    }

    /// Accumulate character data into the innermost frame (flushed on close if
    /// the frame is a leaf).
    pub fn text(&mut self, t: &str) {
        if let Some(f) = self.stack.last_mut() {
            f.text.push_str(t);
        }
    }

    /// Open a `ui:` element: push a frame, emit the opening XHTML events.
    ///
    /// A void element (`img`, `input`) closes itself and has no content; a kind
    /// this target does not project emits nothing.
    pub fn open(
        &mut self,
        kind: &str,
        a: &Attrs,
        h: &mut HtmlSerializer,
    ) -> Result<(), SaxError> {
        let mut f = Frame {
            kind: kind.to_string(),
            text: String::new(),
            closes: Vec::new(),
            leaf: false,
        };
        let title = attr(a, "title").to_string();

        match kind {
            "swap" => {
                // An inert carrier: the runtime applies it once the parser has
                // moved past it, so a streamed fragment is never applied while
                // still half-arrived.  No id: the template is not addressable.
                if !self.swap_runtime {
                    self.swap_runtime = true;
                    inline(h, "script", SWAP_RUNTIME)?;
                }
                let for_ = attr(a, "for");
                let mode = {
                    let m = attr(a, "mode");
                    if m.is_empty() { "replace" } else { m }
                };
                h.xhtml_start(
                    "template",
                    &[("data-axa-swap", for_), ("data-axa-mode", mode)],
                )?;
                f.closes = vec!["template".to_string()];
            }
            "app" => {
                h.xhtml_start("html", &[("lang", "en")])?;
                h.xhtml_start("head", &[])?;
                inline(h, "title", &title)?;
                h.xhtml_start(
                    "meta",
                    &[
                        ("content", "width=device-width,initial-scale=1"),
                        ("name", "viewport"),
                    ],
                )?;
                h.xhtml_end("meta")?;
                // The target's default look; zero specificity, so an app's
                // ui:style still wins (same order as the Perl target).
                inline(h, "style", MATERIAL_CSS)?;
                h.xhtml_end("head")?;
                h.xhtml_start("body", &[])?;
                f.closes = vec!["body".to_string(), "html".to_string()];
            }
            "section" => {
                h.xhtml_start("section", &with_id(Vec::new(), a))?;
                inline(h, "h2", &title)?;
                f.closes = vec!["section".to_string()];
            }
            "navigate" => {
                h.xhtml_start("a", &with_id(vec![("href", attr(a, "to"))], a))?;
                h.text(&title)?;
                f.closes = vec!["a".to_string()];
            }
            "button" => {
                h.xhtml_start("button", &with_id(Vec::new(), a))?;
                h.text(&title)?;
                f.closes = vec!["button".to_string()];
            }
            "image" => {
                let at = with_id(vec![("src", title.as_str()), ("alt", title.as_str())], a);
                h.xhtml_start("img", &at)?;
            }
            "asyncimage" => {
                h.xhtml_start("img", &with_id(vec![("src", attr(a, "url")), ("alt", "")], a))?;
            }
            "audio" => {
                // A transport element, not a leaf: the browser owns play
                // transport, so it stays open for fallback text.
                let src_attr = attr(a, "src");
                let src = if src_attr.is_empty() { title.as_str() } else { src_attr };
                let mut at: Vec<(&str, &str)> =
                    vec![("src", src), ("controls", "controls"), ("preload", "metadata")];
                if !attr(a, "loop").is_empty() {
                    at.push(("loop", "loop"));
                }
                let at = with_id(at, a);
                h.xhtml_start("audio", &at)?;
                f.closes = vec!["audio".to_string()];
            }
            "player" => {
                // The target owns the client runtime; an app emits IR only.
                if !self.player_runtime {
                    self.player_runtime = true;
                    inline(h, "script", PLAYER_RUNTIME)?;
                }
                let mut at: Vec<(&str, &str)> =
                    vec![("class", "player"), ("data-axa-player", "1")];
                if !title.is_empty() {
                    at.push(("aria-label", title.as_str()));
                }
                let at = with_id(at, a);
                h.xhtml_start("figure", &at)?;
                f.closes = vec!["figure".to_string()];
            }
            "equalizer" => {
                // An empty canvas the player runtime paints from the analyser
                // of the transport beside it.
                let bars = eq_bars(a).to_string();
                let at = with_id(
                    vec![
                        ("data-axa-eq", "1"),
                        ("data-bars", bars.as_str()),
                        ("data-mode", eq_mode(a)),
                        ("aria-hidden", "true"),
                    ],
                    a,
                );
                h.xhtml_start("canvas", &at)?;
                f.closes = vec!["canvas".to_string()];
                f.leaf = true;
            }
            "searchable" => {
                h.xhtml_start("input", &with_id(vec![("type", "search")], a))?;
            }
            "form" => {
                let mut at: Vec<(&str, &str)> = Vec::new();
                let method = attr(a, "method");
                if !method.is_empty() {
                    at.push(("method", method));
                }
                let action = attr(a, "action");
                if !action.is_empty() {
                    at.push(("action", action));
                }
                let at = with_id(at, a);
                h.xhtml_start("form", &at)?;
                f.closes = vec!["form".to_string()];
            }
            "select" => {
                let mut at: Vec<(&str, &str)> = Vec::new();
                let name = attr(a, "name");
                if !name.is_empty() {
                    at.push(("name", name));
                }
                let at = with_id(at, a);
                h.xhtml_start("select", &at)?;
                f.closes = vec!["select".to_string()];
            }
            "field" => {
                // A multi-line field is the one field kind that is not void:
                // its value is the textarea's content, flushed on close.
                if attr(a, "type") == "multiline" {
                    let mut at: Vec<(&str, &str)> = Vec::new();
                    for n in ["name", "placeholder"] {
                        let v = attr(a, n);
                        if !v.is_empty() {
                            at.push((n, v));
                        }
                    }
                    let rows = textarea_rows(a);
                    at.push(("rows", rows.as_str()));
                    let at = with_id(at, a);
                    h.xhtml_start("textarea", &at)?;
                    f.closes = vec!["textarea".to_string()];
                    f.text = attr(a, "value").to_string();
                    f.leaf = true;
                }
                else {
                    // a void element: <input> closes itself and has no content
                    let type_attr = attr(a, "type");
                    let ty = match type_attr {
                        "" => "text",
                        "secure" => "password",
                        "toggle" => "checkbox",
                        other => other,
                    };
                    let mut at: Vec<(&str, &str)> = Vec::new();
                    at.push(("type", ty));
                    for n in ["name", "value", "placeholder", "min", "max"] {
                        let v = attr(a, n);
                        if !v.is_empty() {
                            at.push((n, v));
                        }
                    }
                    let at = with_id(at, a);
                    h.xhtml_start("input", &at)?;
                }
            }
            "option" => {
                let mut at: Vec<(&str, &str)> = Vec::new();
                let value = attr(a, "value");
                if !value.is_empty() {
                    at.push(("value", value));
                }
                if !attr(a, "selected").is_empty() {
                    at.push(("selected", "selected"));
                }
                h.xhtml_start("option", &at)?;
                f.closes = vec!["option".to_string()];
                f.leaf = true;
            }
            "cell" => {
                let tag = if attr(a, "header").is_empty() { "td" } else { "th" };
                h.xhtml_start(tag, &with_id(Vec::new(), a))?;
                f.closes = vec![tag.to_string()];
            }
            _ => {
                if let Some((tag, sa)) = static_tag(kind) {
                    let at = with_id(sa.to_vec(), a);
                    h.xhtml_start(tag, &at)?;
                    f.closes = vec![tag.to_string()];
                } else if let Some((tag, sa)) = static_leaf(kind) {
                    // Markdown renders through the swap runtime, so the page
                    // carries it even when no swap fragment is present.
                    if kind == "markdown" && !self.swap_runtime {
                        self.swap_runtime = true;
                        inline(h, "script", SWAP_RUNTIME)?;
                    }
                    let at = with_id(sa.to_vec(), a);
                    h.xhtml_start(tag, &at)?;
                    f.closes = vec![tag.to_string()];
                    f.leaf = true;
                }
            }
        }
        // A cell (<td>/<th>) and an alert (<div role=alert>) hold their text
        // inline: like a leaf, that text is the element's sole content and is
        // flushed on close.
        if kind == "cell" || kind == "alert" {
            f.leaf = true;
        }
        self.stack.push(f);
        Ok(())
    }

    /// Close the innermost element: flush a leaf's accumulated text, then close
    /// its tags (LIFO, matching the serializer's stack).
    pub fn close(&mut self, _kind: &str, h: &mut HtmlSerializer) -> Result<(), SaxError> {
        let f = match self.stack.pop() {
            Some(f) => f,
            None => return Ok(()),
        };
        if f.leaf {
            h.text(&f.text)?;
        }
        for name in f.closes.iter().rev() {
            h.xhtml_end(name)?;
        }
        Ok(())
    }
}

/// `start / text / end` for a small inline element (a heading, a link label).
fn inline(h: &mut HtmlSerializer, ln: &str, t: &str) -> Result<(), SaxError> {
    h.xhtml_start(ln, &[])?;
    h.text(t)?;
    h.xhtml_end(ln)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(name: &str, value: &str) -> Attrs {
        let mut a = Attrs::new();
        a.insert(format!("{{}}{name}"), value.to_string());
        a
    }

    #[test]
    fn player_projects_to_figure_transport_and_canvas() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();

        let mut take = one("title", "take");
        take.insert("{}id".to_string(), "take-player".to_string());
        t.open("player", &take, &mut h).unwrap();
        t.open("audio", &one("src", "/audio/take.mp3"), &mut h).unwrap();
        t.close("audio", &mut h).unwrap();
        let mut eq = one("bars", "24");
        eq.insert("{}mode".to_string(), "wave".to_string());
        eq.insert("{}id".to_string(), "take-eq".to_string());
        t.open("equalizer", &eq, &mut h).unwrap();
        t.close("equalizer", &mut h).unwrap();
        t.close("player", &mut h).unwrap();

        let out = h.into_output();
        assert_eq!(out.matches("<script>").count(), 1, "runtime once per page");
        assert!(out.contains(
            r#"<figure aria-label="take" class="player" data-axa-player="1" id="take-player">"#
        ));
        assert!(out.contains(
            r#"<audio controls="controls" preload="metadata" src="/audio/take.mp3">"#
        ));
        assert!(out.contains(
            r#"<canvas aria-hidden="true" data-axa-eq="1" data-bars="24" data-mode="wave" id="take-eq">"#
        ));
        assert!(out.contains("</canvas>\n</figure>"));
    }

    // `ui:id` is generic: a later swap or an anchor addresses the element by
    // id, so it must ride through exactly as Perl's `_id` does (on every
    // projected element but `option`).
    #[test]
    fn id_rides_through_like_the_perl_target() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();
        let mut sv = one("title", "Status");
        sv.insert("{}id".to_string(), "live-status".to_string());
        t.open("vstack", &sv, &mut h).unwrap();
        t.open("text", &one("id", "live-line"), &mut h).unwrap();
        t.text("rendering…");
        t.close("text", &mut h).unwrap();
        t.close("vstack", &mut h).unwrap();
        t.open("option", &one("id", "no-id-here"), &mut h).unwrap();
        t.close("option", &mut h).unwrap();

        let out = h.into_output();
        assert!(out.contains(r#"<div class="vstack" id="live-status">"#));
        assert!(out.contains(r#"<p id="live-line">"#));
        assert!(out.contains("rendering…"));
        assert!(!out.contains("no-id-here"), "option takes no id (as in Perl)");
    }

    #[test]
    fn swap_projects_to_template_and_emits_runtime_once() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();

        t.open("swap", &one("for", "live"), &mut h).unwrap();
        t.open("vstack", &Attrs::new(), &mut h).unwrap();
        t.close("vstack", &mut h).unwrap();
        t.close("swap", &mut h).unwrap();

        let mut append = one("for", "live");
        append.insert("{}mode".to_string(), "append".to_string());
        t.open("swap", &append, &mut h).unwrap();
        t.close("swap", &mut h).unwrap();

        let out = h.into_output();
        assert_eq!(out.matches("<script>").count(), 1, "swap runtime once per page");
        assert!(out.contains(r#"<template data-axa-mode="replace" data-axa-swap="live">"#));
        assert!(out.contains(r#"<template data-axa-mode="append" data-axa-swap="live">"#));
        assert!(out.contains("</template>"));
        assert!(!out.contains(r#"<template id="#), "swap takes no id (as in Perl)");
    }

    #[test]
    fn markdown_leaf_carries_the_swap_runtime() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();

        t.open("markdown", &one("id", "notes"), &mut h).unwrap();
        t.text("# Heading");
        t.close("markdown", &mut h).unwrap();

        let out = h.into_output();
        assert_eq!(out.matches("<script>").count(), 1, "markdown pulls the runtime");
        assert!(out.contains(r#"<div class="md" data-axa-md="1" id="notes">"#));
        assert!(out.contains("# Heading"));
        assert!(out.contains("data-axa-swap"), "the runtime is the swap one");
    }

    #[test]
    fn multiline_field_projects_to_a_textarea() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();

        let mut a = one("type", "multiline");
        a.insert("{}name".to_string(), "prompt".to_string());
        a.insert("{}placeholder".to_string(), "describe it".to_string());
        a.insert("{}value".to_string(), "line one\nline two".to_string());
        a.insert("{}lines".to_string(), "6".to_string());
        a.insert("{}id".to_string(), "prompt-box".to_string());
        t.open("field", &a, &mut h).unwrap();
        t.close("field", &mut h).unwrap();

        let out = h.into_output();
        assert!(out.contains(
            r#"<textarea id="prompt-box" name="prompt" placeholder="describe it" rows="6">"#
        ));
        assert!(out.contains("line one\nline two"));
        assert!(out.contains("</textarea>"));
        assert!(!out.contains(r#"type="multiline""#), "type selects the tag, it is not an attribute");

        // Perl's shape is `\A\d{1,2}\z` and > 0, else 4.
        for (raw, want) in [("", "4"), ("0", "4"), ("00", "4"), ("007", "4"), ("+5", "4"), ("ab", "4"), ("05", "05"), ("12", "12")] {
            let mut h = HtmlSerializer::new();
            let mut t = HtmlTarget::new();
            let mut a = one("type", "multiline");
            a.insert("{}lines".to_string(), raw.to_string());
            t.open("field", &a, &mut h).unwrap();
            t.close("field", &mut h).unwrap();
            assert!(
                h.output().contains(&format!(r#"rows="{want}""#)),
                "lines={raw} → {want}"
            );
        }
    }

    #[test]
    fn secure_and_toggle_map_to_password_and_checkbox() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();

        t.open("field", &one("type", "secure"), &mut h).unwrap();
        t.close("field", &mut h).unwrap();
        t.open("field", &one("type", "toggle"), &mut h).unwrap();
        t.close("field", &mut h).unwrap();
        t.open("field", &Attrs::new(), &mut h).unwrap();
        t.close("field", &mut h).unwrap();

        let out = h.into_output();
        assert!(out.contains(r#"<input type="password"/>"#));
        assert!(out.contains(r#"<input type="checkbox"/>"#));
        assert!(out.contains(r#"<input type="text"/>"#), "absent type defaults to text");
    }

    #[test]
    fn equalizer_defaults_and_clamps_match_the_perl_target() {
        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();
        t.open("equalizer", &Attrs::new(), &mut h).unwrap();
        t.close("equalizer", &mut h).unwrap();
        assert!(h.output().contains(r#"data-bars="32""#));
        assert!(h.output().contains(r#"data-mode="bars""#));

        let mut h = HtmlSerializer::new();
        let mut t = HtmlTarget::new();
        let mut a = one("bars", "99");
        a.insert("{}mode".to_string(), "spiral".to_string());
        t.open("equalizer", &a, &mut h).unwrap();
        t.close("equalizer", &mut h).unwrap();
        assert!(h.output().contains(r#"data-bars="32""#), "out-of-range bars clamp");
        assert!(h.output().contains(r#"data-mode="bars""#), "unknown mode falls back");

        // Perl's shape is `\A\d{1,2}\z`: a sign or a third digit is not parsed.
        for (raw, want) in [("2", "2"), ("64", "64"), ("007", "32"), ("+5", "32"), ("1", "32")] {
            let mut h = HtmlSerializer::new();
            let mut t = HtmlTarget::new();
            t.open("equalizer", &one("bars", raw), &mut h).unwrap();
            t.close("equalizer", &mut h).unwrap();
            assert!(
                h.output().contains(&format!(r#"data-bars="{want}""#)),
                "bars={raw} → {want}"
            );
        }
    }
}
