/* =========================================================
   STREAM CIPHER
   ========================================================= */


/* =========================================================
   1. RC4
   ========================================================= */

function rc4(key, data) {

  const k = enc.encode(key);

  const S = Array.from(
    { length: 256 },
    (_, i) => i
  );

  if (!k.length) {
    throw Error('Kunci kosong');
  }

  // Key Scheduling Algorithm (KSA)
  for (let i = 0, j = 0; i < 256; i++) {

    j = (
      j +
      S[i] +
      k[i % k.length]
    ) & 255;

    [S[i], S[j]] = [S[j], S[i]];
  }

  // Pseudo-Random Generation Algorithm (PRGA)
  let i = 0;
  let j = 0;

  return data.map(byte => {

    i = (i + 1) & 255;

    j = (
      j +
      S[i]
    ) & 255;

    [S[i], S[j]] = [S[j], S[i]];

    const keystream =
      S[(S[i] + S[j]) & 255];

    return byte ^ keystream;
  });
}


/* =========================================================
   2. LFSR
   ========================================================= */

function lfsr(key, data) {

  let state = 0;

  // Membentuk nilai awal state dari kunci
  for (const char of key) {

    state = (
      state * 31 +
      char.charCodeAt(0)
    ) & 0xffff;
  }

  // Nilai default jika state = 0
  state = state || 0xACE1;

  return data.map(byte => {

    let keystream = 0;

    // Menghasilkan 8 bit keystream
    for (let n = 0; n < 8; n++) {

      const bit = (
        (state >> 0) ^
        (state >> 2) ^
        (state >> 3) ^
        (state >> 5)
      ) & 1;

      state =
        (state >> 1) |
        (bit << 15);

      keystream =
        (keystream << 1) |
        (state & 1);
    }

    return byte ^ keystream;
  });
}


/* =========================================================
   RC4 & LFSR UI
   ========================================================= */

const streamCipher = algorithm => [

  // Enkripsi
  () => hex(
    algorithm(
      K(),
      enc.encode(T())
    )
  ),

  // Dekripsi
  () => dec.decode(
    algorithm(
      K(),
      unhex(T())
    )
  )
];


/* RC4 */

let [rc4Encrypt, rc4Decrypt] =
  streamCipher(rc4);

bind(
  're',
  'ro',
  rc4Encrypt
);

bind(
  'rd',
  'ro',
  rc4Decrypt
);


/* LFSR */

let [lfsrEncrypt, lfsrDecrypt] =
  streamCipher(lfsr);

bind(
  'le',
  'lo',
  lfsrEncrypt
);

bind(
  'ld',
  'lo',
  lfsrDecrypt
);


/* =========================================================
   3. ONE-TIME PAD
   ========================================================= */

card(
  'stm',
  'One-Time Pad',
  'Kunci acak sepanjang pesan, dipakai sekali. Enkripsi membuat kunci acak otomatis dan mengisinya ke kolom di bawah. Simpan kunci itu untuk dekripsi.',

  [
    [
      'otk',
      'Kunci OTP (hex)',
      ''
    ]
  ],

  [
    ['oe', 'Enkripsi'],
    ['od', 'Dekripsi']
  ],

  'oo'
);


/* OTP - Enkripsi */

bind(
  'oe',
  'oo',
  () => {

    const data =
      enc.encode(T());

    const key =
      rnd(data.length);

    // Tampilkan kunci
    $('otk').value =
      hex(key);

    return hex(
      data.map(
        (value, index) =>
          value ^ key[index]
      )
    );
  }
);


/* OTP - Dekripsi */

bind(
  'od',
  'oo',
  () => {

    const cipher =
      unhex(T());

    const key =
      unhex($('otk').value);

    if (key.length !== cipher.length) {
      throw Error(
        'Panjang kunci harus sama dengan ciphertext'
      );
    }

    return dec.decode(
      cipher.map(
        (value, index) =>
          value ^ key[index]
      )
    );
  }
);


/* =========================================================
   4. CHACHA20
   RFC 7539
   ========================================================= */


/* ---------------------------------------------------------
   Rotasi bit ChaCha20
   --------------------------------------------------------- */

function chachaRotl(value, count) {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}


/* ---------------------------------------------------------
   Quarter Round
   --------------------------------------------------------- */

function qr(state, a, b, c, d) {

  state[a] += state[b];

  state[d] =
    chachaRotl(
      state[d] ^ state[a],
      16
    );

  state[c] += state[d];

  state[b] =
    chachaRotl(
      state[b] ^ state[c],
      12
    );

  state[a] += state[b];

  state[d] =
    chachaRotl(
      state[d] ^ state[a],
      8
    );

  state[c] += state[d];

  state[b] =
    chachaRotl(
      state[b] ^ state[c],
      7
    );
}


/* ---------------------------------------------------------
   ChaCha20 Block
   --------------------------------------------------------- */

function chachaBlock(key, counter, nonce) {

  const state =
    new Uint32Array(16);

  const keyView =
    new DataView(
      key.buffer,
      key.byteOffset
    );

  const nonceView =
    new DataView(
      nonce.buffer,
      nonce.byteOffset
    );


  // ChaCha20 constants
  state.set([
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574
  ]);


  // 256-bit key
  for (let i = 0; i < 8; i++) {

    state[4 + i] =
      keyView.getUint32(
        i * 4,
        true
      );
  }


  // Counter
  state[12] =
    counter;


  // 96-bit nonce
  for (let i = 0; i < 3; i++) {

    state[13 + i] =
      nonceView.getUint32(
        i * 4,
        true
      );
  }


  // Salin state awal
  const workingState =
    state.slice();


  // 20 rounds = 10 double rounds
  for (let i = 0; i < 10; i++) {

    // Column rounds

    qr(
      workingState,
      0, 4, 8, 12
    );

    qr(
      workingState,
      1, 5, 9, 13
    );

    qr(
      workingState,
      2, 6, 10, 14
    );

    qr(
      workingState,
      3, 7, 11, 15
    );


    // Diagonal rounds

    qr(
      workingState,
      0, 5, 10, 15
    );

    qr(
      workingState,
      1, 6, 11, 12
    );

    qr(
      workingState,
      2, 7, 8, 13
    );

    qr(
      workingState,
      3, 4, 9, 14
    );
  }


  // Tambahkan state awal
  const output =
    new Uint8Array(64);

  const outputView =
    new DataView(
      output.buffer
    );


  for (let i = 0; i < 16; i++) {

    outputView.setUint32(
      i * 4,
      (
        workingState[i] +
        state[i]
      ) >>> 0,
      true
    );
  }

  return output;
}


/* ---------------------------------------------------------
   ChaCha20
   --------------------------------------------------------- */

function chacha(key, nonce, data) {

  const output =
    new Uint8Array(data.length);


  for (
    let i = 0, counter = 1;
    i < data.length;
    i += 64, counter++
  ) {

    const keystream =
      chachaBlock(
        key,
        counter,
        nonce
      );


    for (
      let j = 0;
      j < 64 && i + j < data.length;
      j++
    ) {

      output[i + j] =
        data[i + j] ^
        keystream[j];
    }
  }

  return output;
}


/* ---------------------------------------------------------
   Membentuk key 256-bit
   --------------------------------------------------------- */

const chachaKey = async () => {

  return new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      enc.encode(K())
    )
  );
};


/* =========================================================
   CHACHA20 UI
   ========================================================= */

card(
  'stm',
  'ChaCha20',
  'Stream cipher modern (RFC 7539). Kunci 256-bit diturunkan dari kunci di tab Pengaturan dengan SHA-256. Output = nonce + ciphertext.',

  [],

  [
    ['ce', 'Enkripsi'],
    ['cd', 'Dekripsi']
  ],

  'co'
);


/* ChaCha20 - Enkripsi */

bind(
  'ce',
  'co',
  async () => {

    const nonce =
      rnd(12);

    const key =
      await chachaKey();

    const plaintext =
      enc.encode(T());

    const ciphertext =
      chacha(
        key,
        nonce,
        plaintext
      );

    return hex(
      cat(
        nonce,
        ciphertext
      )
    );
  }
);


/* ChaCha20 - Dekripsi */

bind(
  'cd',
  'co',
  async () => {

    const raw =
      unhex(T());

    if (raw.length < 13) {
      throw Error(
        'Data terlalu pendek'
      );
    }

    const key =
      await chachaKey();

    const nonce =
      raw.slice(0, 12);

    const ciphertext =
      raw.slice(12);

    return dec.decode(
      chacha(
        key,
        nonce,
        ciphertext
      )
    );
  }
);
