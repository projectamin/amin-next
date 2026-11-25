(function(){
var AC=window.AudioContext||window.webkitAudioContext;
var actx=null,glc=null,gl=null,prog=null,U={},recs=[],loop=false;
function now(){return window.performance.now?performance.now():Date.now()}
function css(el,p){return getComputedStyle(el).getPropertyValue(p).trim()}
function parse(v){
var m,h;
if(!v)return null;
if(v.charAt(0)==='#'){
h=v.slice(1);
if(h.length===3)h=h.charAt(0)+h.charAt(0)+h.charAt(1)+h.charAt(1)+h.charAt(2)+h.charAt(2);
if(h.length!==6)return null;
return [parseInt(h.slice(0,2),16)/255,parseInt(h.slice(2,4),16)/255,parseInt(h.slice(4,6),16)/255]
}
m=v.match(/rgba?\(([^)]+)\)/);
if(m){
var p=m[1].split(',');
if(p.length>2)return [parseFloat(p[0])/255,parseFloat(p[1])/255,parseFloat(p[2])/255]
}
return null
}
function tone(el,a,b,d){
return parse(css(el,a))||parse(css(el,b))||d
}
function palette(el){
return {
bg:tone(el,'--nz-well','--md-surface-container',[0.90,0.88,0.84]),
lo:tone(el,'--nz-muted','--md-outline',[0.48,0.43,0.37]),
sig:tone(el,'--nz-signal','--md-primary',[0.78,0.46,0.10]),
hi:tone(el,'--nz-hi','--md-on-surface',[1,1,1])
}
}
function audioCtx(){
if(actx)return actx;
if(!AC)return null;
try{actx=new AC()}catch(e){actx=null}
return actx
}
function analyser(au){
if(!au)return null;
var an=au._axaAnalyser;
if(an)return an;
var c=audioCtx();
if(!c)return null;
try{
var src=au._axaSource;
if(!src){src=c.createMediaElementSource(au);au._axaSource=src}
an=c.createAnalyser();
an.fftSize=128;
an.smoothingTimeConstant=0.82;
src.connect(an);
an.connect(c.destination);
au._axaAnalyser=an;
}catch(e){an=null}
return an
}
function payload(){
var n=document.querySelector('script[data-axa-vis-shader]');
if(!n)return '';
try{return atob((n.textContent||'').replace(/\s+/g,''))}catch(e){return ''}
}
function compile(type,src){
var s=gl.createShader(type);
if(!s)return null;
gl.shaderSource(s,src);
gl.compileShader(s);
if(!gl.getShaderParameter(s,gl.COMPILE_STATUS)){gl.deleteShader(s);return null}
return s
}
function program(){
if(prog)return prog;
var fsSrc=payload();
if(!fsSrc)return null;
var vs=compile(gl.VERTEX_SHADER,'attribute vec2 a_pos;void main(){gl_Position=vec4(a_pos,0.0,1.0);}');
var fs=compile(gl.FRAGMENT_SHADER,fsSrc);
if(!vs||!fs)return null;
var p=gl.createProgram();
gl.attachShader(p,vs);
gl.attachShader(p,fs);
gl.linkProgram(p);
if(!gl.getProgramParameter(p,gl.LINK_STATUS)){gl.deleteProgram(p);return null}
gl.useProgram(p);
var buf=gl.createBuffer();
gl.bindBuffer(gl.ARRAY_BUFFER,buf);
gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),gl.STATIC_DRAW);
var loc=gl.getAttribLocation(p,'a_pos');
gl.enableVertexAttribArray(loc);
gl.vertexAttribPointer(loc,2,gl.FLOAT,false,0,0);
U.res=gl.getUniformLocation(p,'u_res');
U.time=gl.getUniformLocation(p,'u_time');
U.energy=gl.getUniformLocation(p,'u_energy');
U.mode=gl.getUniformLocation(p,'u_mode');
U.bg=gl.getUniformLocation(p,'u_bg');
U.lo=gl.getUniformLocation(p,'u_lo');
U.sig=gl.getUniformLocation(p,'u_sig');
U.hi=gl.getUniformLocation(p,'u_hi');
prog=p;
return p
}
function context(){
if(gl)return gl;
if(!window.WebGLRenderingContext)return null;
glc=document.createElement('canvas');
try{
gl=glc.getContext('webgl',{alpha:false,antialias:false,depth:false,powerPreference:'low-power'});
if(!gl)gl=glc.getContext('experimental-webgl',{alpha:false,antialias:false,depth:false})
}catch(e){gl=null}
if(!gl)return null;
if(!program()){gl=null;return null}
return gl
}
function pool(w,h){
if(w>glc.width)glc.width=w;
if(h>glc.height)glc.height=h
}
function modeOf(cv){
var m=cv.getAttribute('data-mode');
if(m==='ripple')return 1;
if(m==='vortex')return 2;
return 0
}
function fit(rec){
var cv=rec.cv,dpr=Math.min(window.devicePixelRatio||1,2);
var w=Math.round((cv.clientWidth||320)*dpr),h=Math.round((cv.clientHeight||180)*dpr);
if(!w||!h)return false;
if(cv.width!==w)cv.width=w;
if(cv.height!==h)cv.height=h;
if(!rec.ctx)rec.ctx=cv.getContext('2d');
return rec.ctx?true:false
}
function energy(rec,t){
if(!rec.an)return 0.30+0.10*Math.sin(t*0.0009);
if(rec.au.paused)return 0.16;
rec.an.getByteFrequencyData(rec.freq);
var n=24,i=0,sum=0;
if(n>rec.freq.length)n=rec.freq.length;
while(n>i){sum=sum+rec.freq[i];i++}
return sum/(n*255)
}
function draw(rec,t){
if(!fit(rec))return false;
pool(rec.cv.width,rec.cv.height);
gl.viewport(0,0,rec.cv.width,rec.cv.height);
gl.uniform2f(U.res,rec.cv.width,rec.cv.height);
gl.uniform1f(U.time,t*0.001);
gl.uniform1f(U.energy,energy(rec,t));
gl.uniform1f(U.mode,rec.mode);
gl.uniform3fv(U.bg,rec.pal.bg);
gl.uniform3fv(U.lo,rec.pal.lo);
gl.uniform3fv(U.sig,rec.pal.sig);
gl.uniform3fv(U.hi,rec.pal.hi);
gl.drawArrays(gl.TRIANGLES,0,6);
rec.ctx.clearRect(0,0,rec.cv.width,rec.cv.height);
rec.ctx.drawImage(glc,0,glc.height-rec.cv.height,rec.cv.width,rec.cv.height,0,0,rec.cv.width,rec.cv.height);
return true
}
function fallback(rec){
var cv=rec.cv,g=rec.ctx||cv.getContext('2d');
if(!g)return;
var dpr=Math.min(window.devicePixelRatio||1,2);
var w=Math.round((cv.clientWidth||320)*dpr),h=Math.round((cv.clientHeight||180)*dpr);
if(w>0){
if(h>0){
if(cv.width!==w)cv.width=w;
if(cv.height!==h)cv.height=h
}
}
var s=rec.pal.sig;
g.clearRect(0,0,w,h);
var grd=g.createRadialGradient(w*0.5,h*1.35,4,w*0.5,h*1.35,w*0.85);
grd.addColorStop(0,'rgba('+Math.round(s[0]*255)+','+Math.round(s[1]*255)+','+Math.round(s[2]*255)+',0.42)');
grd.addColorStop(1,'rgba('+Math.round(s[0]*255)+','+Math.round(s[1]*255)+','+Math.round(s[2]*255)+',0)');
g.fillStyle=grd;
g.fillRect(0,0,w,h);
cv.setAttribute('data-axa-vis-fallback','1');
rec.on=false
}
function reduced(){
return window.matchMedia?window.matchMedia('(prefers-reduced-motion: reduce)').matches:false
}
function prune(){
var keep=[],i=0,n=recs.length;
while(n>i){
if(recs[i].cv.isConnected)keep.push(recs[i]);
i++
}
recs=keep
}
function tick(){
loop=false;
prune();
var t=now(),i=0,n=recs.length,live=0;
while(n>i){
var rec=recs[i];
if(rec.on){
if(gl){
if(draw(rec,t))live++
}else fallback(rec)
}
i++
}
if(live>0){if(!reduced()){loop=true;requestAnimationFrame(tick)}}
}
function kick(){
if(loop)return;
if(!context()){
var i=0,n=recs.length;
while(n>i){fallback(recs[i]);i++}
return
}
loop=true;requestAnimationFrame(tick)
}
function bind(cv){
if(!cv||cv.nodeType!==1)return;
if(cv.getAttribute('data-axa-vis')!=='1')return;
if(cv.getAttribute('data-axa-vis-ready')==='1')return;
cv.setAttribute('data-axa-vis-ready','1');
var rec={cv:cv,on:true,ctx:null,an:null,au:null,freq:null,mode:modeOf(cv),pal:palette(cv)};
var fig=cv.closest?cv.closest('[data-axa-player]'):null;
var au=fig?fig.querySelector('audio'):null;
if(!au){
var p=cv.previousElementSibling;
while(p){
if(p.tagName==='AUDIO'){au=p;break}
p=p.previousElementSibling
}
}
if(au){
rec.au=au;
rec.an=analyser(au);
if(rec.an)rec.freq=new Uint8Array(rec.an.frequencyBinCount)
}
if(window.IntersectionObserver){
var io=new IntersectionObserver(function(es){
Array.prototype.forEach.call(es,function(e){
var r=e.target._axaVis;
if(r){
if(e.isIntersecting){r.on=true;kick()}else r.on=false
}
})
},{threshold:0.01});
io.observe(cv)
}
cv._axaVis=rec;
recs.push(rec);
kick()
}
function scan(n){
if(!n||n.nodeType!==1)return;
bind(n);
if(n.querySelectorAll)Array.prototype.forEach.call(n.querySelectorAll('[data-axa-vis]'),bind)
}
function all(){Array.prototype.forEach.call(document.querySelectorAll('[data-axa-vis]'),bind)}
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
while(n>i){recs[i].on=true;i++}
kick()
});
})();
