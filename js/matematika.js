/* 4. Matematika */
const mod=(a,m)=>((a%m)+m)%m;
function mp(b,e,m){let r=1n;b%=m;while(e>0n){if(e&1n)r=r*b%m;b=b*b%m;e>>=1n}return r}
function inv(a,m){let [r0,r1]=[a,m],[s0,s1]=[1n,0n];while(r1){const q=r0/r1;[r0,r1]=[r1,r0-q*r1];[s0,s1]=[s1,s0-q*s1]}
 if(r0!==1n)throw Error('Tidak ada invers modular (nilai tidak koprima)');return mod(s0,m)}
function affine(t,a,b,d){a=BigInt(a);if(a%2n===0n||a%13n===0n)throw Error('a harus koprima dengan 26');
 const ai=Number(inv(mod(a,26n),26n)),A=Number(a);
 return [...t].map(c=>{const u=c>='A'&&c<='Z',l=c>='a'&&c<='z';if(!u&&!l)return c;const base=u?65:97,x=c.charCodeAt(0)-base;
  return String.fromCharCode(base+(d?mod(ai*(x-b),26):mod(A*x+b,26)))}).join('')}
bind('afe','afo',()=>affine($('at').value,$('aa').value,+$('ab').value,false));
bind('afd','afo',()=>affine($('at').value,$('aa').value,+$('ab').value,true));
function rsa(){const p=BigInt($('rp').value),q=BigInt($('rq').value),e=BigInt($('re2').value),n=p*q,phi=(p-1n)*(q-1n);
 if(n<=255n)throw Error('p·q harus lebih besar dari 255');return {n,e,d:inv(e,phi),phi,p,q}}
const rsaInfo=k=>`n = ${k.n}, φ(n) = ${k.phi}\nKunci publik (e, n) = (${k.e}, ${k.n})\nKunci privat (d, n) = (${k.d}, ${k.n})\n\n`;
bind('rsae','rsao',()=>{const k=rsa();return rsaInfo(k)+[...$('rt').value].map(c=>mp(BigInt(c.charCodeAt(0)),k.e,k.n)).join(' ')});
bind('rsad','rsao',()=>{const k=rsa();return rsaInfo(k)+$('rt').value.trim().split(/\s+/).map(x=>String.fromCharCode(Number(mp(BigInt(x),k.d,k.n)))).join('')});
bind('dhb','dho',()=>{const [p,g,a,b]=['dp','dg','da','db'].map(i=>BigInt($(i).value));const A=mp(g,a,p),B=mp(g,b,p),s1=mp(B,a,p),s2=mp(A,b,p);
 return `A = g^a mod p = ${A}\nB = g^b mod p = ${B}\nRahasia versi A = B^a mod p = ${s1}\nRahasia versi B = A^b mod p = ${s2}\n${s1===s2?'Kunci bersama sama.':'Tidak sama, periksa input.'}`});
/* Vigenere */
function vig(t,k,d){k=k.toLowerCase().replace(/[^a-z]/g,'');if(!k)throw Error('Kunci harus berisi huruf');let i=0;
 return [...t].map(c=>{const u=c>='A'&&c<='Z',l=c>='a'&&c<='z';if(!u&&!l)return c;const base=u?65:97,s=k.charCodeAt(i++%k.length)-97;
  return String.fromCharCode(base+mod(c.charCodeAt(0)-base+(d?-s:s),26))}).join('')}
bind('vge','vgo',()=>vig($('vt').value,$('vk').value,false));
bind('vgd','vgo',()=>vig($('vt').value,$('vk').value,true));
/* Rail Fence */
function rail(t,n,d){n=+n;const ch=Array.from(t);if(!(n>=2))throw Error('Jumlah rel minimal 2');const c=2*(n-1);
 const r=ch.map((_,i)=>{const m=i%c;return m<n?m:c-m});
 const order=ch.map((_,i)=>i).sort((x,y)=>r[x]-r[y]||x-y);
 if(!d)return order.map(i=>ch[i]).join('');
 const out=[];order.forEach((idx,j)=>out[idx]=ch[j]);return out.join('')}
bind('rfe','rfo',()=>rail($('rft').value,$('rfn').value,false));
bind('rfd','rfo',()=>rail($('rft').value,$('rfn').value,true));

/* ElGamal, Hill 2x2, kurva eliptik kecil */
card('mat','ElGamal (logaritma diskret)','Gunakan p prima lebih dari 255. Enkripsi per karakter dengan k acak, sehingga hasil berbeda tiap kali. Dekripsi: tempel pasangan c1,c2 dipisah spasi.',
 [['egt','Teks / pasangan','UTS 2026'],['egp','p','467'],['egg','g','2'],['egx','x (kunci privat)','127']],[['ege','Enkripsi'],['egd','Dekripsi']],'ego');
const egv=()=>['egp','egg','egx'].map(i=>BigInt($(i).value));
bind('ege','ego',()=>{const [p,g,x]=egv();if(p<=255n)throw Error('p harus lebih besar dari 255');const y=mp(g,x,p);
 return `Kunci publik (p, g, y) = (${p}, ${g}, ${y})\nKunci privat x = ${x}\n\n`+[...$('egt').value].map(c=>{const k=BigInt(1+Math.floor(Math.random()*Number(p-2n)));return mp(g,k,p)+','+(BigInt(c.charCodeAt(0))*mp(y,k,p)%p)}).join(' ')});
bind('egd','ego',()=>{const [p,,x]=egv();return $('egt').value.trim().split(/\s+/).map(s=>{const [c1,c2]=s.split(',').map(BigInt);return String.fromCharCode(Number(c2*inv(mp(c1,x,p),p)%p))}).join('')});
card('mat','Cipher Hill 2x2 (aljabar matriks)','C = K·P mod 26 untuk pasangan huruf. Kunci: a,b,c,d. Determinan harus koprima dengan 26 (contoh: 3,3,2,5). Hanya huruf A-Z, ganjil ditambah X.',
 [['ht','Teks','HELP ME'],['hk','Kunci a,b,c,d','3,3,2,5']],[['hle','Enkripsi'],['hld','Dekripsi']],'hlo');
function hill(t,ks,d){const [a,b,c,e]=ks.split(',').map(Number);if([a,b,c,e].some(isNaN))throw Error('Kunci harus 4 angka dipisah koma');
 const di=Number(inv(BigInt(mod(a*e-b*c,26)),26n)),m=d?[e,-b,-c,a].map(v=>mod(di*v,26)):[a,b,c,e];
 let s=t.toUpperCase().replace(/[^A-Z]/g,'');if(s.length%2)s+='X';let o='';
 for(let i=0;i<s.length;i+=2){const x=s.charCodeAt(i)-65,y=s.charCodeAt(i+1)-65;o+=String.fromCharCode(65+mod(m[0]*x+m[1]*y,26),65+mod(m[2]*x+m[3]*y,26))}return o}
bind('hle','hlo',()=>hill($('ht').value,$('hk').value,false));bind('hld','hlo',()=>hill($('ht').value,$('hk').value,true));
card('mat','Kurva eliptik kecil (ECC): y² = x³ + ax + b mod p','Hitung kelipatan titik kG dan pertukaran kunci ECDH versi kecil. Contoh: p=17, a=2, b=2, G=(5,1).',
 [['ecp','p','17'],['eca','a','2'],['ecb','b','2'],['ecx','G x','5'],['ecy','G y','1'],['ek1','Kunci privat A','3'],['ek2','Kunci privat B','7']],[['ecr','Hitung']],'eco2');
bind('ecr','eco2',()=>{const [p,a,b,gx,gy,k1,k2]=['ecp','eca','ecb','ecx','ecy','ek1','ek2'].map(i=>BigInt($(i).value)),bm=(v,m)=>((v%m)+m)%m;
 if(bm(gy*gy-gx**3n-a*gx-b,p)!==0n)throw Error('G tidak terletak pada kurva');
 const add=(P,Q)=>{if(!P)return Q;if(!Q)return P;if(P[0]===Q[0]&&bm(P[1]+Q[1],p)===0n)return null;
  const l=P[0]===Q[0]?bm((3n*P[0]**2n+a)*inv(bm(2n*P[1],p),p),p):bm((Q[1]-P[1])*inv(bm(Q[0]-P[0],p),p),p),x=bm(l*l-P[0]-Q[0],p);return [x,bm(l*(P[0]-x)-P[1],p)]},
  mul=(k,P)=>{let R=null,Q=P;while(k>0n){if(k&1n)R=add(R,Q);Q=add(Q,Q);k>>=1n}return R},f=P=>P?`(${P[0]}, ${P[1]})`:'O (titik tak hingga)';
 let r='Kelipatan titik G:\n';for(let i=1n;i<=8n;i++)r+=`${i}G = ${f(mul(i,[gx,gy]))}\n`;
 const A=mul(k1,[gx,gy]),B=mul(k2,[gx,gy]);
 return r+`\nKunci publik A = ${k1}G = ${f(A)}\nKunci publik B = ${k2}G = ${f(B)}\nRahasia versi A = ${k1}·B = ${f(mul(k1,B))}\nRahasia versi B = ${k2}·A = ${f(mul(k2,A))}`});
