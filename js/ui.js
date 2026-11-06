/* Tabs */
const names=[['Pengaturan','s0'],['1. Block Cipher','blk'],['2. Stream Cipher','stm'],['3. Fungsi Utama','fun'],['4. Dasar Matematika','mat']];
names.forEach(([n,id],i)=>{const b=document.createElement('button');b.textContent=n;b.setAttribute('role','tab');b.onclick=()=>show(i);$('tabs').append(b)});
function show(i){names.forEach(([,id],j)=>{$(id).classList.toggle('on',i===j);$('tabs').children[j].setAttribute('aria-selected',i===j)})}
show(0);

/* Tombol pakai hasil sebagai input */
['fo','ao','ro','lo','mo','oo','co'].forEach(id=>{const b=document.createElement('button'),lbl='Pakai hasil sebagai input';b.className='use';b.textContent=lbl;
 b.onclick=()=>{const v=$(id).textContent.trim();
  if(/^([0-9a-f]{2})+$/i.test(v)){$('txt').value=v;b.textContent='Sudah dipakai. Klik Dekripsi.'}
  else b.textContent='Hasil bukan hex. Jalankan Enkripsi dulu.';
  setTimeout(()=>b.textContent=lbl,2500)};
 $(id).after(b)});
