/*
 * SecurePair v. 0.5.0 - 03/10/2026
 *
 * Cryptographically secure pairing and communication between ESP32 boards:
 * pair through a single standard LED with the LX.25 protocol, or over
 * ESP-NOW and LoRa.
 *
 * Copyright (C) 2026 under Apache License, Version 2.0
 *
 * @author Luca Soltoggio
 * https://www.lucasoltoggio.it
 * https://github.com/toggio/SecurePair
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * Portable X25519 and AES-256-GCM, for the host tests.
 *
 * X25519 follows TweetNaCl (public domain). AES and GHASH are the textbook
 * versions: correct, not fast, not hardened. On ESP32 Mbed TLS is used instead.
 */

#if !defined(ESP_PLATFORM) || defined(SECUREPAIR_PORTABLE_CRYPTO)

#include <string.h>

#include <chrono>
#include <random>

#include "Crypto.h"

namespace securepair {
namespace crypto {

uint32_t hardwareRandom32() {
  static std::random_device rd;
  return rd();
}

uint32_t cycleCount() {
  return (uint32_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
}

// --- X25519 -----------------------------------------------------------------

namespace {

typedef int64_t gf[16];

void car25519(gf o) {
  for (int i = 0; i < 16; ++i) {
    o[i] += (int64_t)1 << 16;
    const int64_t c = o[i] >> 16;
    if (i < 15) {
      o[i + 1] += c - 1;
    } else {
      o[0] += 38 * (c - 1);
    }
    o[i] -= c * 65536;
  }
}

void sel25519(gf p, gf q, int b) {
  const int64_t c = ~(int64_t)(b - 1);
  for (int i = 0; i < 16; ++i) {
    const int64_t t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

void pack25519(uint8_t *o, const gf n) {
  gf m, t;
  for (int i = 0; i < 16; ++i) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (int j = 0; j < 2; ++j) {
    m[0] = t[0] - 0xffed;
    for (int i = 1; i < 15; ++i) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    const int b = (int)((m[15] >> 16) & 1);
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }
  for (int i = 0; i < 16; ++i) {
    o[2 * i] = (uint8_t)(t[i] & 0xff);
    o[2 * i + 1] = (uint8_t)(t[i] >> 8);
  }
}

void unpack25519(gf o, const uint8_t *n) {
  for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
  o[15] &= 0x7fff;
}

void add(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

void sub(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

void mul(gf o, const gf a, const gf b) {
  int64_t t[31] = {};
  for (int i = 0; i < 16; ++i)
    for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
  for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
  for (int i = 0; i < 16; ++i) o[i] = t[i];
  car25519(o);
  car25519(o);
}

void sqr(gf o, const gf a) { mul(o, a, a); }

void inv25519(gf o, const gf in) {
  gf c;
  for (int a = 0; a < 16; ++a) c[a] = in[a];
  for (int a = 253; a >= 0; --a) {
    sqr(c, c);
    if (a != 2 && a != 4) mul(c, c, in);
  }
  for (int a = 0; a < 16; ++a) o[a] = c[a];
}

}  // namespace

bool x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t peerPub[32]) {
  static const gf k121665 = {0xDB41, 1};
  uint8_t z[32];
  memcpy(z, priv, 32);
  z[31] = (z[31] & 127) | 64;
  z[0] &= 248;
  gf x, a, b, c, d, e, f;
  unpack25519(x, peerPub);
  for (int i = 0; i < 16; ++i) {
    b[i] = x[i];
    d[i] = a[i] = c[i] = 0;
  }
  a[0] = d[0] = 1;
  for (int i = 254; i >= 0; --i) {
    const int r = (z[i >> 3] >> (i & 7)) & 1;
    sel25519(a, b, r);
    sel25519(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    sqr(d, e);
    sqr(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    sqr(b, a);
    sub(c, d, f);
    mul(a, c, k121665);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    sqr(b, e);
    sel25519(a, b, r);
    sel25519(c, d, r);
  }
  inv25519(c, c);
  mul(a, a, c);
  pack25519(out, a);
  wipe(z, sizeof(z));
  uint8_t acc = 0;
  for (int i = 0; i < 32; ++i) acc |= out[i];
  return acc != 0;
}

// --- AES-256 ----------------------------------------------------------------

namespace {

uint8_t sbox[256];
bool sboxReady = false;

uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  while (b) {
    if (b & 1) p ^= a;
    a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
    b >>= 1;
  }
  return p;
}

void buildSbox() {
  for (int x = 0; x < 256; ++x) {
    uint8_t inv = 0;
    if (x) {
      // x^254 = x^-1 in GF(2^8)
      uint8_t r = 1, base = (uint8_t)x;
      for (int e = 254; e; e >>= 1) {
        if (e & 1) r = gmul(r, base);
        base = gmul(base, base);
      }
      inv = r;
    }
    uint8_t s = inv;
    for (int i = 1; i <= 4; ++i) s ^= (uint8_t)((inv << i) | (inv >> (8 - i)));
    sbox[x] = s ^ 0x63;
  }
  sboxReady = true;
}

struct Aes256 {
  uint8_t rk[240];

  explicit Aes256(const uint8_t key[32]) {
    if (!sboxReady) buildSbox();
    memcpy(rk, key, 32);
    uint8_t rcon = 1;
    for (int i = 8; i < 60; ++i) {
      uint8_t t[4];
      memcpy(t, rk + 4 * (i - 1), 4);
      if (i % 8 == 0) {
        const uint8_t u = t[0];
        t[0] = sbox[t[1]] ^ rcon;
        t[1] = sbox[t[2]];
        t[2] = sbox[t[3]];
        t[3] = sbox[u];
        rcon = gmul(rcon, 2);
      } else if (i % 8 == 4) {
        for (int j = 0; j < 4; ++j) t[j] = sbox[t[j]];
      }
      for (int j = 0; j < 4; ++j) rk[4 * i + j] = rk[4 * (i - 8) + j] ^ t[j];
    }
  }

  ~Aes256() { wipe(rk, sizeof(rk)); }

  void encrypt(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[i];
    for (int round = 1; round <= 14; ++round) {
      uint8_t t[16];
      for (int i = 0; i < 16; ++i) t[i] = sbox[s[i]];
      // ShiftRows: row r of column c comes from column c + r
      for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r) s[4 * c + r] = t[4 * ((c + r) % 4) + r];
      if (round != 14) {
        for (int c = 0; c < 4; ++c) {
          uint8_t *col = s + 4 * c;
          const uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
          col[0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
          col[1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
          col[2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
          col[3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }
      }
      for (int i = 0; i < 16; ++i) s[i] ^= rk[16 * round + i];
    }
    memcpy(out, s, 16);
  }
};

// GHASH multiplication in GF(2^128), bit-reflected as in the GCM spec.
void gfMul(uint8_t x[16], const uint8_t h[16]) {
  uint8_t z[16] = {}, v[16];
  memcpy(v, h, 16);
  for (int i = 0; i < 128; ++i) {
    if (x[i / 8] & (0x80 >> (i % 8)))
      for (int j = 0; j < 16; ++j) z[j] ^= v[j];
    const bool lsb = v[15] & 1;
    for (int j = 15; j > 0; --j) v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
    v[0] >>= 1;
    if (lsb) v[0] ^= 0xe1;
  }
  memcpy(x, z, 16);
}

void ghashData(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len) {
  while (len > 0) {
    const size_t n = len < 16 ? len : 16;
    for (size_t i = 0; i < n; ++i) y[i] ^= data[i];
    gfMul(y, h);
    data += n;
    len -= n;
  }
}

void gcmCore(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadLen,
             const uint8_t *in, size_t len, uint8_t *out, bool encrypting, uint8_t tag[16]) {
  const Aes256 aes(key);
  uint8_t h[16] = {}, j0[16], ctr[16], ks[16];
  aes.encrypt(h, h);
  memcpy(j0, iv, 12);
  j0[12] = j0[13] = j0[14] = 0;
  j0[15] = 1;

  uint8_t y[16] = {};
  ghashData(y, h, aad, aadLen);
  if (!encrypting) ghashData(y, h, in, len);

  memcpy(ctr, j0, 16);
  for (size_t off = 0; off < len; off += 16) {
    for (int i = 15; i >= 12; --i)
      if (++ctr[i]) break;
    aes.encrypt(ctr, ks);
    const size_t n = len - off < 16 ? len - off : 16;
    for (size_t i = 0; i < n; ++i) out[off + i] = in[off + i] ^ ks[i];
  }
  if (encrypting) ghashData(y, h, out, len);

  uint8_t lens[16];
  const uint64_t aBits = (uint64_t)aadLen * 8, cBits = (uint64_t)len * 8;
  for (int i = 0; i < 8; ++i) {
    lens[i] = (uint8_t)(aBits >> (56 - 8 * i));
    lens[8 + i] = (uint8_t)(cBits >> (56 - 8 * i));
  }
  ghashData(y, h, lens, 16);
  aes.encrypt(j0, ks);
  for (int i = 0; i < 16; ++i) tag[i] = ks[i] ^ y[i];
}

}  // namespace

bool gcmEncrypt(const uint8_t key[32], const uint8_t iv[kGcmIvLen], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out,
                uint8_t tag[kGcmTagLen]) {
  gcmCore(key, iv, aad, aadLen, in, len, out, true, tag);
  return true;
}

bool gcmDecrypt(const uint8_t key[32], const uint8_t iv[kGcmIvLen], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out,
                const uint8_t tag[kGcmTagLen]) {
  uint8_t calc[16];
  gcmCore(key, iv, aad, aadLen, in, len, out, false, calc);
  if (!equal(calc, tag, 16)) {
    wipe(out, len);
    return false;
  }
  return true;
}

}  // namespace crypto
}  // namespace securepair

#endif
