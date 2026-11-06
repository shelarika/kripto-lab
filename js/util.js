const $=id=>document.getElementById(id);
const enc=new TextEncoder(),dec=new TextDecoder();
const hex=b=>[...b].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex=s=>{s=s.replace(/\s/g,'');if(!/^([0-9a-f]{2})+$/i.test(s))throw Error('Input harus berupa hex yang valid');return Uint8Array.from(s.match(/../g),h=>parseInt(h,16))};
const cat=(...a)=>Uint8Array.from(a.flatMap(x=>[...x]));
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
function bind(btn,out,fn){const el=$(btn);if(!el)return;el.onclick=async()=>{try{$(out).textContent=await fn()}catch(e){$(out).textContent='Error: '+e.message}}}
const T=()=>$('txt').value, K=()=>$('key').value;

/* Pembuat kartu UI: fields = [id,label,nilai,tipe|opsi[]] ; buttons = [id,nama] */
function card(sec,title,desc,fields,buttons,out){if(!$(sec))return;const d=document.createElement('div');d.className='card';
 d.innerHTML=`<h2>${title}</h2><p>${desc}</p>`+fields.map(([id,l,v,t])=>`<label for="${id}">${l}</label>`+(Array.isArray(t)?`<select id="${id}">${t.map(o=>`<option>${o}</option>`).join('')}</select>`:`<input id="${id}" type="${t||'text'}" value="${v}">`)).join('')
 +`<div class="btns">${buttons.map(([id,n])=>`<button id="${id}">${n}</button>`).join('')}</div><pre id="${out}"></pre>`;$(sec).append(d)}
