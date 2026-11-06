/* 3. Fungsi utama */
bind('hb','ho',async()=>{const d=enc.encode($('hm').value);let r='';
 for(const alg of['SHA-1','SHA-256','SHA-512'])r+=alg+'\n'+hex(new Uint8Array(await crypto.subtle.digest(alg,d)))+'\n\n';return r.trim()});
bind('hmb','hmo',async()=>{const k=await crypto.subtle.importKey('raw',enc.encode($('hk').value),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return hex(new Uint8Array(await crypto.subtle.sign('HMAC',k,enc.encode($('hm').value))))});
let kp=null,sig=null;
bind('sg','so',async()=>{kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 sig=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},kp.privateKey,enc.encode($('hm').value)));return 'Tanda tangan dibuat:\n'+hex(sig)});
bind('vf','so',async()=>{if(!sig)throw Error('Buat tanda tangan dulu');
 const ok=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},kp.publicKey,sig,enc.encode($('hm').value));
 return ok?'VALID: pesan asli dan ditandatangani pemilik kunci.':'TIDAK VALID: pesan berubah atau tanda tangan palsu.'});

/* RSA-OAEP, ECDH, ringkasan klasifikasi */
let rk=null;
card('fun','Enkripsi asimetris RSA-OAEP (2048-bit)','Enkripsi dengan kunci publik, dekripsi dengan kunci privat. Memakai teks di tab Pengaturan (maks. sekitar 190 karakter). Kunci dibuat saat Enkripsi pertama.',[],[['oae','Enkripsi'],['oad','Dekripsi']],'oao');
bind('oae','oao',async()=>{rk=rk||await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},false,['encrypt','decrypt']);
 return hex(new Uint8Array(await crypto.subtle.encrypt({name:'RSA-OAEP'},rk.publicKey,enc.encode(T()))))});
bind('oad','oao',async()=>{if(!rk)throw Error('Enkripsi dulu agar kunci dibuat');
 try{return dec.decode(await crypto.subtle.decrypt({name:'RSA-OAEP'},rk.privateKey,unhex(T())))}catch{throw Error('Gagal dekripsi: data bukan hasil enkripsi sesi ini')}});
card('fun','Pertukaran kunci ECDH (kurva P-256)','Dua pihak membuat pasangan kunci, saling bertukar kunci publik, dan menurunkan rahasia yang sama.',[],[['ech','Jalankan']],'eco');
bind('ech','eco',async()=>{const g=()=>crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),A=await g(),B=await g(),
 d=async(p,q)=>hex(new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:q.publicKey},p.privateKey,256))),s1=await d(A,B),s2=await d(B,A);
 return 'Rahasia versi A:\n'+s1+'\nRahasia versi B:\n'+s2+'\n'+(s1===s2?'Sama: kunci bersama berhasil disepakati.':'Berbeda.')});
card('fun','Ringkasan: klasifikasi algoritma berdasarkan fungsi utama','Hubungan fungsi, algoritma, dan tempatnya di aplikasi ini.',[],[],'sumo');
if($('sumo'))$('sumo').textContent=`Enkripsi simetris : AES-GCM, DES, Feistel (tab Block), RC4, ChaCha20 (tab Stream)
Enkripsi asimetris: RSA-OAEP (tab ini), RSA dan ElGamal (tab Matematika)
Fungsi hash       : SHA-1, SHA-256, SHA-512
Autentikasi pesan : HMAC-SHA256
Tanda tangan      : ECDSA P-256
Pertukaran kunci  : ECDH (tab ini), Diffie-Hellman (tab Matematika)`;
