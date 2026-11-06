/* 1. Block cipher: Feistel */
function roundKeys(key){let h=2166136261;for(const c of key){h^=c.charCodeAt(0);h=Math.imul(h,16777619)>>>0}
 return Array.from({length:8},(_,i)=>{h=(Math.imul(h^i,2654435761)+0x7f4a7c15)>>>0;return h})}
function F(r,k){let x=Math.imul(r^k,0x9E3779B1)>>>0;x=((x<<5)|(x>>>27))>>>0;return (x^(x>>>13))>>>0}
function feistel(b,keys,decrypt){const v=new DataView(b.buffer,b.byteOffset,8);let L=v.getUint32(0),R=v.getUint32(4);
 for(const k of decrypt?[...keys].reverse():keys){[L,R]=[R,(L^F(R,k))>>>0]}
 const o=new Uint8Array(8),w=new DataView(o.buffer);w.setUint32(0,R);w.setUint32(4,L);return o}
function feEnc(text,key){const keys=roundKeys(key),d=enc.encode(text),p=8-d.length%8,m=cat(d,new Uint8Array(p).fill(p)),iv=rnd(8),out=[];let prev=iv;
 for(let i=0;i<m.length;i+=8){const blk=m.slice(i,i+8).map((x,j)=>x^prev[j]);prev=feistel(blk,keys,false);out.push(...prev)}
 return hex(cat(iv,out))}
function feDec(h,key){const keys=roundKeys(key),d=unhex(h);if(d.length<16||d.length%8)throw Error('Panjang ciphertext tidak valid');
 let prev=d.slice(0,8);const out=[];for(let i=8;i<d.length;i+=8){const c=d.slice(i,i+8),p=feistel(c,keys,true).map((x,j)=>x^prev[j]);out.push(...p);prev=c}
 const pad=out[out.length-1];if(!pad||pad>8)throw Error('Kunci salah atau data rusak');return dec.decode(Uint8Array.from(out.slice(0,-pad)))}
/* 1b. AES-GCM */
async function aesKey(pw,salt){const m=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},m,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
bind('ae','ao',async()=>{const salt=rnd(16),iv=rnd(12);
 const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},await aesKey(K(),salt),enc.encode(T())));return hex(cat(salt,iv,ct))});
bind('ad','ao',async()=>{const d=unhex(T());if(d.length<45)throw Error('Data terlalu pendek');
 try{return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:d.slice(16,28)},await aesKey(K(),d.slice(0,16)),d.slice(28)))}
 catch{throw Error('Kunci salah atau data diubah (autentikasi GCM gagal)')}});

/* DES + mode operasi (ECB, CBC, CFB, OFB, CTR) */
const nums=s=>s.trim().split(/\s+/).map(Number);
const D_IP=nums('58 50 42 34 26 18 10 2 60 52 44 36 28 20 12 4 62 54 46 38 30 22 14 6 64 56 48 40 32 24 16 8 57 49 41 33 25 17 9 1 59 51 43 35 27 19 11 3 61 53 45 37 29 21 13 5 63 55 47 39 31 23 15 7');
const D_FP=nums('40 8 48 16 56 24 64 32 39 7 47 15 55 23 63 31 38 6 46 14 54 22 62 30 37 5 45 13 53 21 61 29 36 4 44 12 52 20 60 28 35 3 43 11 51 19 59 27 34 2 42 10 50 18 58 26 33 1 41 9 49 17 57 25');
const D_E=nums('32 1 2 3 4 5 4 5 6 7 8 9 8 9 10 11 12 13 12 13 14 15 16 17 16 17 18 19 20 21 20 21 22 23 24 25 24 25 26 27 28 29 28 29 30 31 32 1');
const D_P=nums('16 7 20 21 29 12 28 17 1 15 23 26 5 18 31 10 2 8 24 14 32 27 3 9 19 13 30 6 22 11 4 25');
const D_PC1=nums('57 49 41 33 25 17 9 1 58 50 42 34 26 18 10 2 59 51 43 35 27 19 11 3 60 52 44 36 63 55 47 39 31 23 15 7 62 54 46 38 30 22 14 6 61 53 45 37 29 21 13 5 28 20 12 4');
const D_PC2=nums('14 17 11 24 1 5 3 28 15 6 21 10 23 19 12 4 26 8 16 7 27 20 13 2 41 52 31 37 47 55 30 40 51 45 33 48 44 49 39 56 34 53 46 42 50 36 29 32');
const D_SH=nums('1 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1');
const D_S=[
'14 4 13 1 2 15 11 8 3 10 6 12 5 9 0 7 0 15 7 4 14 2 13 1 10 6 12 11 9 5 3 8 4 1 14 8 13 6 2 11 15 12 9 7 3 10 5 0 15 12 8 2 4 9 1 7 5 11 3 14 10 0 6 13',
'15 1 8 14 6 11 3 4 9 7 2 13 12 0 5 10 3 13 4 7 15 2 8 14 12 0 1 10 6 9 11 5 0 14 7 11 10 4 13 1 5 8 12 6 9 3 2 15 13 8 10 1 3 15 4 2 11 6 7 12 0 5 14 9',
'10 0 9 14 6 3 15 5 1 13 12 7 11 4 2 8 13 7 0 9 3 4 6 10 2 8 5 14 12 11 15 1 13 6 4 9 8 15 3 0 11 1 2 12 5 10 14 7 1 10 13 0 6 9 8 7 4 15 14 3 11 5 2 12',
'7 13 14 3 0 6 9 10 1 2 8 5 11 12 4 15 13 8 11 5 6 15 0 3 4 7 2 12 1 10 14 9 10 6 9 0 12 11 7 13 15 1 3 14 5 2 8 4 3 15 0 6 10 1 13 8 9 4 5 11 12 7 2 14',
'2 12 4 1 7 10 11 6 8 5 3 15 13 0 14 9 14 11 2 12 4 7 13 1 5 0 15 10 3 9 8 6 4 2 1 11 10 13 7 8 15 9 12 5 6 3 0 14 11 8 12 7 1 14 2 13 6 15 0 9 10 4 5 3',
'12 1 10 15 9 2 6 8 0 13 3 4 14 7 5 11 10 15 4 2 7 12 9 5 6 1 13 14 0 11 3 8 9 14 15 5 2 8 12 3 7 0 4 10 1 13 11 6 4 3 2 12 9 5 15 10 11 14 1 7 6 0 8 13',
'4 11 2 14 15 0 8 13 3 12 9 7 5 10 6 1 13 0 11 7 4 9 1 10 14 3 5 12 2 15 8 6 1 4 11 13 12 3 7 14 10 15 6 8 0 5 9 2 6 11 13 8 1 4 10 7 9 5 0 15 14 2 3 12',
'13 2 8 4 6 15 11 1 10 9 3 14 5 0 12 7 1 15 13 8 10 3 7 4 12 5 6 11 0 14 9 2 7 11 4 1 9 12 14 2 0 6 10 13 15 3 5 8 2 1 14 7 4 10 8 13 15 12 9 0 3 5 6 11'].map(nums);
const perm=(b,t)=>t.map(i=>b[i-1]);
const toBits=a=>[...a].flatMap(x=>Array.from({length:8},(_,i)=>(x>>(7-i))&1));
const fromBits=b=>Uint8Array.from({length:b.length/8},(_,i)=>b.slice(i*8,i*8+8).reduce((s,v)=>s*2+v,0));
function desKeys(k8){const b=perm(toBits(k8),D_PC1);let C=b.slice(0,28),D=b.slice(28);
 return D_SH.map(s=>{C=C.slice(s).concat(C.slice(0,s));D=D.slice(s).concat(D.slice(0,s));return perm(C.concat(D),D_PC2)})}
function desBlock(blk,ks,decrypt){const b=perm(toBits(blk),D_IP);let L=b.slice(0,32),R=b.slice(32);
 for(let i=0;i<16;i++){const k=ks[decrypt?15-i:i],x=perm(R,D_E).map((v,j)=>v^k[j]),o=[];
  for(let s=0;s<8;s++){const c=x.slice(s*6,s*6+6),v=D_S[s][(c[0]*2+c[5])*16+c[1]*8+c[2]*4+c[3]*2+c[4]];o.push((v>>3)&1,(v>>2)&1,(v>>1)&1,v&1)}
  const f=perm(o,D_P);[L,R]=[R,L.map((v,j)=>v^f[j])]}
 return fromBits(perm(R.concat(L),D_FP))}
function engine(name,key){if(name==='DES'){const kb=new Uint8Array(8);kb.set(enc.encode(key).slice(0,8));const ks=desKeys(kb);return [b=>desBlock(b,ks,false),b=>desBlock(b,ks,true)]}
 const ks=roundKeys(key);return [b=>feistel(b,ks,false),b=>feistel(b,ks,true)]}
function runMode(mode,decrypt,data,E,D,iv){const out=[],n=data.length;
 if(mode==='ECB'||mode==='CBC'){let d=data;if(!decrypt){const p=8-n%8;d=cat(data,new Uint8Array(p).fill(p))}
  if(d.length%8||!d.length)throw Error('Panjang data tidak valid');let prev=iv;
  for(let i=0;i<d.length;i+=8){const b=d.slice(i,i+8);
   if(!decrypt){prev=E(mode==='CBC'?b.map((v,j)=>v^prev[j]):b);out.push(...prev)}
   else{const p=D(b);out.push(...(mode==='CBC'?p.map((v,j)=>v^prev[j]):p));prev=b}}
  if(decrypt){const pd=out[out.length-1];if(!pd||pd>8)throw Error('Kunci salah atau data rusak');out.length-=pd}
  return Uint8Array.from(out)}
 let reg=iv.slice(),ctr=0;
 for(let i=0;i<n;i+=8){const b=data.slice(i,i+8);let ks;
  if(mode==='CTR'){const blk=iv.slice();new DataView(blk.buffer).setUint32(4,ctr++);ks=E(blk)}else ks=E(reg);
  const o=b.map((v,j)=>v^ks[j]);out.push(...o);if(mode==='OFB')reg=ks;if(mode==='CFB')reg=decrypt?b:o}
 return Uint8Array.from(out)}
card('blk','DES dan mode operasi blok (ECB, CBC, CFB, OFB, CTR)','Pilih cipher blok (DES 16 ronde atau Feistel mini) dan mode operasi. Enkripsi memakai teks dan kunci di tab Pengaturan. Kunci DES diambil 8 karakter pertama.',
 [['mciph','Cipher blok','',['DES','Feistel mini']],['mmode','Mode operasi','',['CBC','ECB','CFB','OFB','CTR']]],[['me','Enkripsi'],['md','Dekripsi'],['mdemo','Demo pola ECB']],'mo');
bind('me','mo',()=>modeRun(false));bind('md','mo',()=>modeRun(true));
function modeRun(decrypt){const mode=$('mmode').value,[E,D]=engine($('mciph').value,K()),iv8=mode!=='ECB';
 if(!decrypt){const iv=rnd(8),ct=runMode(mode,false,enc.encode(T()),E,D,iv);return hex(iv8?cat(iv,ct):ct)}
 const raw=unhex(T());return dec.decode(runMode(mode,true,iv8?raw.slice(8):raw,E,D,iv8?raw.slice(0,8):new Uint8Array(8)))}
bind('mdemo','mo',()=>{const [E,D]=engine($('mciph').value,K()),d=enc.encode('ABCDEFGHABCDEFGHABCDEFGH'),g=h=>h.match(/.{1,16}/g).join(' ');
 return 'Plaintext: 3 blok identik (ABCDEFGH)\nECB: '+g(hex(runMode('ECB',false,d,E,D,rnd(8))))+'\nCBC: '+g(hex(runMode('CBC',false,d,E,D,rnd(8))))+'\n\nECB menghasilkan blok yang sama untuk plaintext yang sama, sehingga pola bocor. CBC tidak.'});
