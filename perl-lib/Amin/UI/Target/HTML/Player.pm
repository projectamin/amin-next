package Amin::UI::Target::HTML::Player;
use v5.38; use warnings; use utf8;

# Client half of ui:player / ui:equalizer.  The target owns it: an app emits
# <ui:player> IR and never writes script itself, so the trust boundary stays
# where Amin::Handler::HTML draws it.  The runtime finds each
# [data-axa-player] figure, routes its <audio> through one shared AudioContext
# and AnalyserNode, and paints the child <canvas data-axa-eq>.
#
# Like the swap runtime, the text is character data inside <script>, so it must
# stay XML-safe: no raw '<' and no '&&' (the page is parsed as XHTML by the
# tests and by any downstream XML consumer).  Loops are written `n > i` and
# boolean tests are nested for that reason, not for style.
#
# Players arrive twice: in the first document and inside a later ui:swap, so a
# MutationObserver binds swapped-in figures the same way.  Binding is
# idempotent (data-axa-player-ready) and the analyser is cached on the audio
# element — a MediaElementSource may only be created once per element.

our $RUNTIME = <<'JS';
(function(){
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
JS

1;
