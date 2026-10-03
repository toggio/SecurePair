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
 * Portable part of the cryptography: SHA-256, HMAC, HKDF, random pool.
 */

#include "Crypto.h"

#include <string.h>

#include <mutex>

namespace securepair {
namespace crypto {

namespace {

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

void Sha256::reset() {
  static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(h_, init, sizeof(h_));
  total_ = 0;
  used_ = 0;
}

void Sha256::block(const uint8_t *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i)
    w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
  for (int i = 16; i < 64; ++i) {
    const uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; ++i) {
    const uint32_t t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
    const uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void Sha256::update(const void *data, size_t len) {
  const uint8_t *p = static_cast<const uint8_t *>(data);
  total_ += len;
  while (len > 0) {
    size_t n = 64 - used_;
    if (n > len) n = len;
    memcpy(buf_ + used_, p, n);
    used_ += n;
    p += n;
    len -= n;
    if (used_ == 64) {
      block(buf_);
      used_ = 0;
    }
  }
}

void Sha256::finish(uint8_t out[kHashLen]) {
  const uint64_t bits = total_ * 8;
  const uint8_t pad = 0x80;
  update(&pad, 1);
  const uint8_t zero = 0;
  while (used_ != 56) update(&zero, 1);
  uint8_t len[8];
  for (int i = 0; i < 8; ++i) len[i] = (uint8_t)(bits >> (56 - 8 * i));
  update(len, 8);
  for (int i = 0; i < 8; ++i) {
    out[4 * i] = (uint8_t)(h_[i] >> 24);
    out[4 * i + 1] = (uint8_t)(h_[i] >> 16);
    out[4 * i + 2] = (uint8_t)(h_[i] >> 8);
    out[4 * i + 3] = (uint8_t)h_[i];
  }
  wipe(buf_, sizeof(buf_));
  reset();
}

void sha256(const void *data, size_t len, uint8_t out[kHashLen]) {
  Sha256 s;
  s.update(data, len);
  s.finish(out);
}

void HmacSha256::begin(const uint8_t *key, size_t keyLen) {
  uint8_t k[64] = {};
  if (keyLen > 64) {
    sha256(key, keyLen, k);
  } else {
    memcpy(k, key, keyLen);
  }
  uint8_t ipad[64];
  for (int i = 0; i < 64; ++i) {
    ipad[i] = k[i] ^ 0x36;
    opad_[i] = k[i] ^ 0x5c;
  }
  inner_.reset();
  inner_.update(ipad, 64);
  wipe(k, sizeof(k));
  wipe(ipad, sizeof(ipad));
}

void HmacSha256::finish(uint8_t out[kHashLen]) {
  uint8_t ih[kHashLen];
  inner_.finish(ih);
  Sha256 outer;
  outer.update(opad_, 64);
  outer.update(ih, kHashLen);
  outer.finish(out);
  wipe(opad_, sizeof(opad_));
  wipe(ih, sizeof(ih));
}

void hmacSha256(const uint8_t *key, size_t keyLen, const void *data, size_t len,
                uint8_t out[kHashLen]) {
  HmacSha256 h;
  h.begin(key, keyLen);
  h.update(data, len);
  h.finish(out);
}

void hkdfExtract(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen,
                 uint8_t prk[kHashLen]) {
  const uint8_t zeros[kHashLen] = {};
  if (saltLen == 0) {
    salt = zeros;
    saltLen = kHashLen;
  }
  hmacSha256(salt, saltLen, ikm, ikmLen, prk);
}

void hkdfExpand(const uint8_t prk[kHashLen], const char *info, uint8_t *out, size_t outLen) {
  uint8_t t[kHashLen];
  size_t tLen = 0;
  for (uint8_t counter = 1; outLen > 0; ++counter) {
    HmacSha256 h;
    h.begin(prk, kHashLen);
    h.update(t, tLen);
    h.update(info, strlen(info));
    h.update(&counter, 1);
    h.finish(t);
    tLen = kHashLen;
    const size_t n = outLen < kHashLen ? outLen : kHashLen;
    memcpy(out, t, n);
    out += n;
    outLen -= n;
  }
  wipe(t, sizeof(t));
}

bool equal(const void *a, const void *b, size_t len) {
  const volatile uint8_t *x = static_cast<const volatile uint8_t *>(a);
  const volatile uint8_t *y = static_cast<const volatile uint8_t *>(b);
  uint8_t d = 0;
  for (size_t i = 0; i < len; ++i) d |= x[i] ^ y[i];
  return d == 0;
}

void wipe(void *p, size_t len) {
  volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
  while (len--) *v++ = 0;
}

// --- Random pool ------------------------------------------------------------

namespace {
uint8_t pool[kHashLen];
uint32_t poolCounter = 0;
std::mutex poolMutex;   // the pairing task and the application may draw at the same time
}  // namespace

void addEntropy(const void *data, size_t len) {
  std::lock_guard<std::mutex> lock(poolMutex);
  Sha256 s;
  s.update("pool-add", 8);
  s.update(pool, sizeof(pool));
  s.update(data, len);
  const uint32_t t = cycleCount();
  s.update(&t, sizeof(t));
  s.finish(pool);
}

void randomBytes(void *out, size_t len) {
  std::lock_guard<std::mutex> lock(poolMutex);
  uint8_t *p = static_cast<uint8_t *>(out);
  while (len > 0) {
    // Refresh the pool with fresh hardware randomness, then derive the output
    // from it with a different label: the output never reveals the pool.
    uint32_t hw[8];
    for (int i = 0; i < 8; ++i) hw[i] = hardwareRandom32();
    const uint32_t extra[2] = {++poolCounter, cycleCount()};
    Sha256 s;
    s.update("pool-next", 9);
    s.update(pool, sizeof(pool));
    s.update(hw, sizeof(hw));
    s.update(extra, sizeof(extra));
    s.finish(pool);
    uint8_t block[kHashLen];
    s.update("pool-out", 8);
    s.update(pool, sizeof(pool));
    s.finish(block);
    const size_t n = len < kHashLen ? len : kHashLen;
    memcpy(p, block, n);
    wipe(block, sizeof(block));
    wipe(hw, sizeof(hw));
    p += n;
    len -= n;
  }
}

bool x25519Keypair(uint8_t priv[32], uint8_t pub[32]) {
  randomBytes(priv, 32);
  priv[0] &= 248;
  priv[31] &= 127;
  priv[31] |= 64;
  static const uint8_t basePoint[32] = {9};
  return x25519(pub, priv, basePoint);
}

}  // namespace crypto
}  // namespace securepair
