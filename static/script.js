/* CyberScan Pro v2 — Main Script */

// PARTICLE CANVAS
(function(){
  const c=document.getElementById('particles');
  if(!c)return;
  const ctx=c.getContext('2d');
  let W,H,pts=[];
  function resize(){W=c.width=window.innerWidth;H=c.height=window.innerHeight;}
  resize();window.addEventListener('resize',resize);
  class P{
    constructor(){this.reset();}
    reset(){this.x=Math.random()*W;this.y=Math.random()*H;this.s=Math.random()*1.4+0.3;this.dx=(Math.random()-.5)*.3;this.dy=(Math.random()-.5)*.3;this.o=Math.random()*.45+.08;this.col=Math.random()>.5?'#00ffc8':'#00aaff';}
    update(){this.x+=this.dx;this.y+=this.dy;if(this.x<0||this.x>W||this.y<0||this.y>H)this.reset();}
    draw(){ctx.beginPath();ctx.arc(this.x,this.y,this.s,0,Math.PI*2);ctx.fillStyle=this.col;ctx.globalAlpha=this.o;ctx.fill();ctx.globalAlpha=1;}
  }
  for(let i=0;i<120;i++)pts.push(new P());
  function draw(){ctx.clearRect(0,0,W,H);pts.forEach(p=>{p.update();p.draw();});requestAnimationFrame(draw);}
  draw();
})();

// SCAN LOADER
function startScan(e){
  const url=document.getElementById('urlInput')?.value.trim();
  if(!url)return;
  const loader=document.getElementById('loader');
  const ss=document.querySelector('.scanner-section');
  const vb=document.querySelector('.vuln-banner');
  const rs=document.querySelector('.recent-section');
  if(ss)ss.style.opacity='0';if(vb)vb.style.opacity='0';if(rs)rs.style.opacity='0';
  setTimeout(()=>{if(loader)loader.classList.remove('hidden');},300);
  const domain=url.replace(/^https?:\/\//,'').split('/')[0];
  const de=document.getElementById('loaderDomain');
  if(de)de.textContent='TARGET: '+domain.toUpperCase();
  const msgs=[
    'Resolving DNS records...','Establishing SSL handshake...','Checking certificate expiry...',
    'Probing security headers...','Scanning X-Frame-Options...','Checking Content-Security-Policy...',
    'Verifying HSTS enforcement...','Sweeping common ports...','Checking for exposed files...',
    'Scanning .env and config files...','Testing HTTP methods...','Fingerprinting technology stack...',
    'Calculating CVSS-style score...','Building risk assessment...','Generating analysis report...'
  ];
  let i=0;
  const me=document.getElementById('loaderMsg');
  const be=document.getElementById('loaderBar');
  const iv=setInterval(()=>{
    if(i<msgs.length){if(me)me.textContent=msgs[i];if(be)be.style.width=((i+1)/msgs.length*90)+'%';i++;}
  },900);
  window.addEventListener('beforeunload',()=>clearInterval(iv));
}

// MODALS
function openModal(id){const m=document.getElementById(id);if(m){m.classList.add('active');document.body.style.overflow='hidden';}}
function closeModal(e,id){if(e&&e.target!==e.currentTarget)return;const m=document.getElementById(id);if(m){m.classList.remove('active');document.body.style.overflow='';}}
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal-overlay.active').forEach(m=>{m.classList.remove('active');document.body.style.overflow='';});});

// SCROLL ANIMATIONS
(function(){
  const els=document.querySelectorAll('.vuln-card,.analysis-card,.score-card,.chart-card,.dl-btn,.stat-card');
  if(!els.length)return;
  const obs=new IntersectionObserver((entries)=>{
    entries.forEach((entry,i)=>{
      if(entry.isIntersecting){
        setTimeout(()=>{entry.target.style.opacity='1';entry.target.style.transform='translateY(0)';},i*55);
        obs.unobserve(entry.target);
      }
    });
  },{threshold:.05});
  els.forEach(el=>{el.style.opacity='0';el.style.transform='translateY(16px)';el.style.transition='opacity .4s ease, transform .4s ease';obs.observe(el);});
})();
