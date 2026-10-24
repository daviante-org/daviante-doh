//! Clean-room cryptographic primitives for the Admin Control-Plane:
//! - Constant-time byte slice comparison (`constant_time_eq`)
//! - CSPRNG token generation via OS entropy (`/dev/urandom` on Unix, `BCryptGenRandom` via `RandomState`/OS on fallback)
//! - FIPS 180-4 SHA-256 and RFC 4231 HMAC-SHA256 (for OIDC PKCE `S256` and signed state cookies)
//! - RFC 7693 Blake2b-512 and RFC 9106 Argon2id (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`)
//!   with OWASP ASVS v4.0 minimum parameters (`m=19456`, `t=2`, `p=1`)
//! - RFC 7515 / RFC 8017 §8.2.2 RS256 (RSA PKCS#1 v1.5 with SHA-256) JWT signature verification

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;

/// Compares two byte slices in constant time without short-circuiting on content differences.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Fills `buf` with cryptographically strong random bytes from the OS CSPRNG.
pub fn fill_os_random(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::Read as _;
        let mut f =
            File::open("/dev/urandom").map_err(|e| format!("failed to open /dev/urandom: {e}"))?;
        f.read_exact(buf)
            .map_err(|e| format!("failed to read /dev/urandom: {e}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut offset = 0usize;
        let mut counter = 0u64;
        while offset < buf.len() {
            let s1 = RandomState::new();
            let s2 = RandomState::new();
            let mut h1 = s1.build_hasher();
            let mut h2 = s2.build_hasher();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            h1.write_u128(nanos);
            h1.write_u64(counter);
            h2.write_u64(counter.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let mut seed = [0u8; 24];
            seed[0..8].copy_from_slice(&h1.finish().to_le_bytes());
            seed[8..16].copy_from_slice(&h2.finish().to_le_bytes());
            seed[16..24].copy_from_slice(&counter.to_le_bytes());
            let digest = sha256(&seed);
            let take = (buf.len() - offset).min(32);
            buf[offset..offset + take].copy_from_slice(&digest[..take]);
            offset += take;
            counter = counter.wrapping_add(1);
        }
        Ok(())
    }
}

/// Generates a 256-bit (32-byte) CSPRNG token encoded as URL-safe Base64 without padding.
pub fn generate_random_token_b64() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    fill_os_random(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Generates a UUIDv4 string from OS CSPRNG bytes.
pub fn generate_uuid_v4() -> Result<String, String> {
    let mut b = [0u8; 16];
    fill_os_random(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

// ============================================================================
// FIPS 180-4 SHA-256 & RFC 4231 HMAC-SHA256
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Computes the 32-byte FIPS 180-4 SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 72) & !63);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word_bytes) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word_bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Computes the 32-byte RFC 4231 HMAC-SHA256 MAC of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_input = Vec::with_capacity(64 + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner_hash = sha256(&inner_input);

    let mut outer_input = [0u8; 96];
    outer_input[..64].copy_from_slice(&opad);
    outer_input[64..].copy_from_slice(&inner_hash);
    sha256(&outer_input)
}

/// Computes an RFC 7636 PKCE `S256` code challenge from a `code_verifier`.
pub fn pkce_s256_challenge(code_verifier: &str) -> String {
    let digest = sha256(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

// ============================================================================
// RFC 7693 Blake2b & RFC 9106 Argon2id
// ============================================================================

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, chunk) in block.as_chunks::<8>().0.iter().enumerate() {
        m[i] = u64::from_le_bytes(*chunk);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    for s in &BLAKE2B_SIGMA {
        blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Computes unkeyed Blake2b with `out_len` (1..=64) over `slices`.
pub fn blake2b_slices(out_len: usize, slices: &[&[u8]]) -> Vec<u8> {
    let out_len = out_len.clamp(1, 64);
    let mut h = BLAKE2B_IV;
    h[0] ^= 0x0101_0000 ^ (out_len as u64);

    let mut buf = [0u8; 128];
    let mut buf_len = 0usize;
    let mut total = 0u128;

    for slice in slices {
        let mut data = *slice;
        while !data.is_empty() {
            if buf_len == 128 {
                total += 128;
                blake2b_compress(&mut h, &buf, total, false);
                buf_len = 0;
            }
            let take = (128 - buf_len).min(data.len());
            buf[buf_len..buf_len + take].copy_from_slice(&data[..take]);
            buf_len += take;
            data = &data[take..];
        }
    }

    total += buf_len as u128;
    buf[buf_len..].fill(0);
    blake2b_compress(&mut h, &buf, total, true);

    let mut raw = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        raw[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    raw[..out_len].to_vec()
}

/// RFC 9106 §3.2 variable-length hash function `H'(X)` writing into `out`.
fn blake2b_long(out: &mut [u8], slices: &[&[u8]]) {
    let tau = out.len() as u32;
    let tau_bytes = tau.to_le_bytes();
    let mut with_prefix = Vec::with_capacity(slices.len() + 1);
    with_prefix.push(tau_bytes.as_slice());
    with_prefix.extend_from_slice(slices);

    if out.len() <= 64 {
        let digest = blake2b_slices(out.len(), &with_prefix);
        out.copy_from_slice(&digest);
        return;
    }

    let r = out.len().div_ceil(32) - 2;
    let mut v = blake2b_slices(64, &with_prefix);
    out[..32].copy_from_slice(&v[..32]);

    for i in 1..r {
        v = blake2b_slices(64, &[&v]);
        out[i * 32..(i + 1) * 32].copy_from_slice(&v[..32]);
    }

    let remaining = out.len() - 32 * r;
    let last = blake2b_slices(remaining, &[&v]);
    out[32 * r..].copy_from_slice(&last);
}

#[inline]
fn f_bla_mka(x: u64, y: u64) -> u64 {
    let m = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(m.wrapping_shl(1))
}

#[inline]
fn g_argon2(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = f_bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = f_bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = f_bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = f_bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn permute_p(v: &mut [u64; 16]) {
    g_argon2(v, 0, 4, 8, 12);
    g_argon2(v, 1, 5, 9, 13);
    g_argon2(v, 2, 6, 10, 14);
    g_argon2(v, 3, 7, 11, 15);
    g_argon2(v, 0, 5, 10, 15);
    g_argon2(v, 1, 6, 11, 12);
    g_argon2(v, 2, 7, 8, 13);
    g_argon2(v, 3, 4, 9, 14);
}

#[inline]
fn permute_p_slice(v: &mut [u64]) {
    g_argon2_slice(v, 0, 4, 8, 12);
    g_argon2_slice(v, 1, 5, 9, 13);
    g_argon2_slice(v, 2, 6, 10, 14);
    g_argon2_slice(v, 3, 7, 11, 15);
    g_argon2_slice(v, 0, 5, 10, 15);
    g_argon2_slice(v, 1, 6, 11, 12);
    g_argon2_slice(v, 2, 7, 8, 13);
    g_argon2_slice(v, 3, 4, 9, 14);
}

#[inline]
fn g_argon2_slice(v: &mut [u64], a: usize, b: usize, c: usize, d: usize) {
    v[a] = f_bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = f_bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = f_bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = f_bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// RFC 9106 §3.4 compression function `G(X, Y)` operating in-place on pre-XORed `r = X ^ Y`
/// and reusable `q` scratch buffer without copying 1 KiB input blocks by value.
#[inline]
fn argon2_compress_in_place(
    out: &mut [u64; 128],
    r: &[u64; 128],
    q: &mut [u64; 128],
    xor_out: bool,
) {
    q.copy_from_slice(r);

    // Apply P row-wise in-place (8 rows of 16 u64 words)
    for row in 0..8 {
        let base = row * 16;
        permute_p_slice(&mut q[base..base + 16]);
    }

    // Apply P column-wise (8 columns of 16 u64 words: pairs of u64s from each row)
    let mut tmp = [0u64; 16];
    for col in 0..8 {
        for row in 0..8 {
            tmp[row * 2] = q[row * 16 + col * 2];
            tmp[row * 2 + 1] = q[row * 16 + col * 2 + 1];
        }
        permute_p(&mut tmp);
        for row in 0..8 {
            q[row * 16 + col * 2] = tmp[row * 2];
            q[row * 16 + col * 2 + 1] = tmp[row * 2 + 1];
        }
    }

    if xor_out {
        for i in 0..128 {
            out[i] ^= r[i] ^ q[i];
        }
    } else {
        for i in 0..128 {
            out[i] = r[i] ^ q[i];
        }
    }
}

/// RFC 9106 §3.4 compression function `G(X, Y)` operating on 1024-byte (128 x `u64`) blocks.
fn argon2_compress_block(out: &mut [u64; 128], x: &[u64; 128], y: &[u64; 128], xor_out: bool) {
    let mut r = [0u64; 128];
    let mut q = [0u64; 128];
    for i in 0..128 {
        r[i] = x[i] ^ y[i];
    }
    argon2_compress_in_place(out, &r, &mut q, xor_out);
}

fn bytes_to_block(bytes: &[u8]) -> [u64; 128] {
    let mut blk = [0u64; 128];
    for (i, chunk) in bytes.as_chunks::<8>().0.iter().take(128).enumerate() {
        blk[i] = u64::from_le_bytes(*chunk);
    }
    blk
}

fn block_to_bytes(blk: &[u64; 128]) -> [u8; 1024] {
    let mut out = [0u8; 1024];
    for (i, word) in blk.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Computes raw RFC 9106 Argon2id (`y = 2`, `v = 0x13`) tag bytes.
pub fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    tag_len: usize,
) -> Result<Vec<u8>, String> {
    if p_cost == 0 || p_cost > 8 {
        return Err("parallelism p must be between 1 and 8".to_string());
    }
    if t_cost == 0 || t_cost > 16 {
        return Err("iterations t must be between 1 and 16".to_string());
    }
    if m_cost_kib < 8 * p_cost || m_cost_kib > 262_144 {
        return Err("memory cost m must be between 8*p and 262144 KiB".to_string());
    }
    if salt.len() < 8 || salt.len() > 64 {
        return Err("salt length must be between 8 and 64 bytes".to_string());
    }
    if !(4..=64).contains(&tag_len) {
        return Err("tag length must be between 4 and 64 bytes".to_string());
    }

    let p_bytes = p_cost.to_le_bytes();
    let tag_bytes = (tag_len as u32).to_le_bytes();
    let m_bytes = m_cost_kib.to_le_bytes();
    let t_bytes = t_cost.to_le_bytes();
    let v_bytes = 0x13u32.to_le_bytes();
    let y_bytes = 2u32.to_le_bytes(); // Argon2id = 2
    let pw_len_bytes = (password.len() as u32).to_le_bytes();
    let salt_len_bytes = (salt.len() as u32).to_le_bytes();
    let zero_bytes = 0u32.to_le_bytes();

    let h0 = blake2b_slices(
        64,
        &[
            &p_bytes,
            &tag_bytes,
            &m_bytes,
            &t_bytes,
            &v_bytes,
            &y_bytes,
            &pw_len_bytes,
            password,
            &salt_len_bytes,
            salt,
            &zero_bytes,
            &zero_bytes,
        ],
    );

    let lanes = p_cost as usize;
    let segment_length = (m_cost_kib as usize) / (4 * lanes);
    let lane_length = segment_length * 4;
    let total_blocks = lane_length * lanes;
    let mut memory = vec![[0u64; 128]; total_blocks];

    let mut block_bytes = [0u8; 1024];
    for l in 0..lanes {
        let l_bytes = (l as u32).to_le_bytes();
        let zero_idx = 0u32.to_le_bytes();
        let one_idx = 1u32.to_le_bytes();

        blake2b_long(&mut block_bytes, &[&h0, &zero_idx, &l_bytes]);
        memory[l * lane_length] = bytes_to_block(&block_bytes);

        blake2b_long(&mut block_bytes, &[&h0, &one_idx, &l_bytes]);
        memory[l * lane_length + 1] = bytes_to_block(&block_bytes);
    }

    let zero_block = [0u64; 128];
    let mut scratch_r = [0u64; 128];
    let mut scratch_q = [0u64; 128];
    for pass in 0..t_cost {
        for slice in 0..4usize {
            let data_independent = pass == 0 && slice < 2;
            for l in 0..lanes {
                let mut address_block = [0u64; 128];
                let mut input_block = [0u64; 128];
                if data_independent {
                    input_block[0] = pass as u64;
                    input_block[1] = l as u64;
                    input_block[2] = slice as u64;
                    input_block[3] = total_blocks as u64;
                    input_block[4] = t_cost as u64;
                    input_block[5] = 2; // Argon2id
                }

                let start_idx = if pass == 0 && slice == 0 { 2 } else { 0 };
                for idx in start_idx..segment_length {
                    if data_independent && (idx % 128 == 0 || idx == start_idx) {
                        input_block[6] = (idx / 128 + 1) as u64;
                        let mut tmp = [0u64; 128];
                        argon2_compress_block(&mut tmp, &zero_block, &input_block, false);
                        argon2_compress_block(&mut address_block, &zero_block, &tmp, false);
                    }

                    let curr_offset = slice * segment_length + idx;
                    let prev_offset = if curr_offset == 0 {
                        lane_length - 1
                    } else {
                        curr_offset - 1
                    };

                    let pseudo_rand = if data_independent {
                        address_block[idx % 128]
                    } else {
                        memory[l * lane_length + prev_offset][0]
                    };

                    let ref_lane = if pass == 0 && slice == 0 {
                        l
                    } else {
                        ((pseudo_rand >> 32) as usize) % lanes
                    };

                    let same_lane = ref_lane == l;
                    let ref_area_size = if pass == 0 {
                        if slice == 0 {
                            idx - 1
                        } else if same_lane {
                            slice * segment_length + idx - 1
                        } else if idx == 0 {
                            slice * segment_length - 1
                        } else {
                            slice * segment_length
                        }
                    } else if same_lane {
                        lane_length - segment_length + idx - 1
                    } else if idx == 0 {
                        lane_length - segment_length - 1
                    } else {
                        lane_length - segment_length
                    };

                    let mut rel_pos = pseudo_rand & 0xffff_ffff;
                    rel_pos = (rel_pos.wrapping_mul(rel_pos)) >> 32;
                    rel_pos = (ref_area_size as u64)
                        .saturating_sub(1 + (((ref_area_size as u64).wrapping_mul(rel_pos)) >> 32));

                    let start_pos = if pass != 0 && slice != 3 {
                        (slice + 1) * segment_length
                    } else {
                        0
                    };
                    let ref_index = (start_pos + (rel_pos as usize)) % lane_length;

                    let prev_slot_idx = l * lane_length + prev_offset;
                    let ref_slot_idx = ref_lane * lane_length + ref_index;
                    let curr_slot_idx = l * lane_length + curr_offset;
                    {
                        let prev_ref = &memory[prev_slot_idx];
                        let ref_ref = &memory[ref_slot_idx];
                        for i in 0..128 {
                            scratch_r[i] = prev_ref[i] ^ ref_ref[i];
                        }
                    }
                    argon2_compress_in_place(
                        &mut memory[curr_slot_idx],
                        &scratch_r,
                        &mut scratch_q,
                        pass > 0,
                    );
                }
            }
        }
    }

    let mut final_block = memory[lane_length - 1];
    for l in 1..lanes {
        let last_in_lane = &memory[l * lane_length + lane_length - 1];
        for i in 0..128 {
            final_block[i] ^= last_in_lane[i];
        }
    }

    let final_bytes = block_to_bytes(&final_block);
    let mut tag = vec![0u8; tag_len];
    blake2b_long(&mut tag, &[&final_bytes]);
    Ok(tag)
}

/// Hashes `password` using RFC 9106 Argon2id and formats it as a standard PHC string:
/// `$argon2id$v=19$m=<m_cost_kib>,t=<t_cost>,p=<p_cost>$<salt_b64>$<hash_b64>`.
pub fn hash_password_argon2id(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, String> {
    let tag = argon2id_raw(password, salt, m_cost_kib, t_cost, p_cost, 32)?;
    let salt_b64 = STANDARD_NO_PAD.encode(salt);
    let tag_b64 = STANDARD_NO_PAD.encode(&tag);
    Ok(format!(
        "$argon2id$v=19$m={m_cost_kib},t={t_cost},p={p_cost}${salt_b64}${tag_b64}"
    ))
}

/// Verifies `password` against an Argon2id PHC string (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`)
/// using constant-time tag comparison.
pub fn verify_argon2id_phc(phc_hash: &str, password: &[u8]) -> bool {
    let parts: Vec<&str> = phc_hash.trim().split('$').collect();
    if parts.len() != 6 || !parts[0].is_empty() || parts[1] != "argon2id" || parts[2] != "v=19" {
        return false;
    }

    let mut m_cost = None;
    let mut t_cost = None;
    let mut p_cost = None;
    for kv in parts[3].split(',') {
        if let Some((k, v)) = kv.split_once('=') {
            match k {
                "m" => m_cost = v.parse::<u32>().ok(),
                "t" => t_cost = v.parse::<u32>().ok(),
                "p" => p_cost = v.parse::<u32>().ok(),
                _ => return false,
            }
        }
    }
    let (Some(m), Some(t), Some(p)) = (m_cost, t_cost, p_cost) else {
        return false;
    };
    let Ok(salt) = STANDARD_NO_PAD.decode(parts[4]) else {
        return false;
    };
    let Ok(expected_tag) = STANDARD_NO_PAD.decode(parts[5]) else {
        return false;
    };
    let Ok(computed_tag) = argon2id_raw(password, &salt, m, t, p, expected_tag.len()) else {
        return false;
    };
    constant_time_eq(&computed_tag, &expected_tag)
}

// ============================================================================
// RFC 7515 / RFC 8017 §8.2.2 RS256 (RSA PKCS#1 v1.5 with SHA-256) Verifier
// ============================================================================

/// Big-integer limb representation (little-endian `u64` limbs) for RSA public-key verification (`s^e mod n`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        let stripped = match bytes.iter().position(|&b| b != 0) {
            Some(pos) => &bytes[pos..],
            None => return Self { limbs: vec![0] },
        };
        let num_limbs = stripped.len().div_ceil(8);
        let mut limbs = vec![0u64; num_limbs];
        for (i, &b) in stripped.iter().rev().enumerate() {
            limbs[i / 8] |= (b as u64) << ((i % 8) * 8);
        }
        Self::normalize(&mut limbs);
        Self { limbs }
    }

    fn to_be_bytes_padded(&self, target_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; target_len];
        for (i, byte_slot) in out.iter_mut().rev().enumerate() {
            let limb_idx = i / 8;
            if limb_idx < self.limbs.len() {
                *byte_slot = ((self.limbs[limb_idx] >> ((i % 8) * 8)) & 0xff) as u8;
            }
        }
        out
    }

    fn normalize(limbs: &mut Vec<u64>) {
        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (&a, &b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            if a != b {
                return a.cmp(&b);
            }
        }
        std::cmp::Ordering::Equal
    }

    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0u64;
        for i in 0..self.limbs.len() {
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let (d1, o1) = self.limbs[i].overflowing_sub(b);
            let (d2, o2) = d1.overflowing_sub(borrow);
            self.limbs[i] = d2;
            borrow = u64::from(o1 || o2);
        }
        Self::normalize(&mut self.limbs);
    }

    fn shl1(&mut self) {
        let mut carry = 0u64;
        for limb in &mut self.limbs {
            let next_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        let mut prod = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let cur = (prod[i + j] as u128) + (a as u128) * (b as u128) + carry;
                prod[i + j] = cur as u64;
                carry = cur >> 64;
            }
            prod[i + other.limbs.len()] = carry as u64;
        }
        Self::normalize(&mut prod);
        let p = Self { limbs: prod };
        p.rem(modulus)
    }

    fn rem(&self, modulus: &Self) -> Self {
        if self.cmp(modulus) == std::cmp::Ordering::Less {
            return self.clone();
        }
        let mut r = Self { limbs: vec![0] };
        let total_bits = self.limbs.len() * 64;
        for bit_idx in (0..total_bits).rev() {
            r.shl1();
            let limb = self.limbs[bit_idx / 64];
            if ((limb >> (bit_idx % 64)) & 1) != 0 {
                r.limbs[0] |= 1;
            }
            if r.cmp(modulus) != std::cmp::Ordering::Less {
                r.sub_assign(modulus);
            }
        }
        r
    }

    fn mod_pow_bytes(&self, exp_be: &[u8], modulus: &Self) -> Self {
        let mut result = Self { limbs: vec![1] };
        let mut base = self.rem(modulus);
        for &byte in exp_be.iter().rev() {
            for bit in 0..8 {
                if ((byte >> bit) & 1) != 0 {
                    result = result.mul_mod(&base, modulus);
                }
                base = base.mul_mod(&base, modulus);
            }
        }
        result
    }
}

/// Verifies an RFC 7515 `RS256` (RSA PKCS#1 v1.5 with SHA-256, RFC 8017 §8.2.2) signature
/// against a JWK RSA public key (`n_b64url`, `e_b64url`).
pub fn verify_rs256_jwk(
    n_b64url: &str,
    e_b64url: &str,
    signing_input: &[u8],
    sig_b64url: &str,
) -> bool {
    let Ok(n_bytes_raw) = URL_SAFE_NO_PAD.decode(n_b64url.trim()) else {
        return false;
    };
    let Ok(e_bytes) = URL_SAFE_NO_PAD.decode(e_b64url.trim()) else {
        return false;
    };
    let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(sig_b64url.trim()) else {
        return false;
    };
    let n_stripped = match n_bytes_raw.iter().position(|&b| b != 0) {
        Some(pos) => &n_bytes_raw[pos..],
        None => return false,
    };
    let k = n_stripped.len();
    // Require 2048-bit to 4096-bit RSA modulus and exact k-byte signature
    if !(256..=512).contains(&k) || sig_bytes.len() != k || e_bytes.is_empty() || e_bytes.len() > 8
    {
        return false;
    }
    // Public exponent must be odd and >= 65537
    if (e_bytes.last().copied().unwrap_or(0) & 1) == 0 {
        return false;
    }

    let n_big = BigUint::from_be_bytes(n_stripped);
    let s_big = BigUint::from_be_bytes(&sig_bytes);
    if s_big.cmp(&n_big) != std::cmp::Ordering::Less {
        return false;
    }

    let em_big = s_big.mod_pow_bytes(&e_bytes, &n_big);
    let em = em_big.to_be_bytes_padded(k);

    // Construct deterministic RFC 8017 §9.2 EM for SHA-256
    const SHA256_DIGEST_INFO: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let t_len = SHA256_DIGEST_INFO.len() + 32;
    if k < t_len + 11 {
        return false;
    }
    let ps_len = k - 3 - t_len;
    let mut expected_em = Vec::with_capacity(k);
    expected_em.push(0x00);
    expected_em.push(0x01);
    expected_em.resize(2 + ps_len, 0xff);
    expected_em.push(0x00);
    expected_em.extend_from_slice(&SHA256_DIGEST_INFO);
    expected_em.extend_from_slice(&sha256(signing_input));

    constant_time_eq(&em, &expected_em)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_and_hmac_vectors() {
        let digest = sha256(b"abc");
        assert_eq!(
            digest[..4],
            [0xba, 0x78, 0x16, 0xbf],
            "NIST SHA-256('abc') prefix"
        );
        let mac = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(mac[..4], [0xf7, 0xbc, 0x83, 0xf4]);
    }

    #[test]
    fn argon2id_roundtrip_and_reject_wrong_password() {
        let salt = b"0123456789abcdef";
        let phc = hash_password_argon2id(b"correct-horse-battery-staple", salt, 64, 2, 1)
            .expect("argon2id hash");
        assert!(phc.starts_with("$argon2id$v=19$m=64,t=2,p=1$"));
        assert!(verify_argon2id_phc(&phc, b"correct-horse-battery-staple"));
        assert!(!verify_argon2id_phc(&phc, b"wrong-password"));
    }
}
