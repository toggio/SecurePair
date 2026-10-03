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
 * Cryptographic primitives.
 *
 * SHA-256, HMAC and HKDF are portable code, the same everywhere. X25519 and
 * AES-256-GCM come from Mbed TLS on ESP32 (hardware AES) and from a small
 * portable implementation on the PC, used only by the host tests.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace securepair {
namespace crypto {

constexpr size_t kHashLen = 32;
constexpr size_t kGcmIvLen = 12;
constexpr size_t kGcmTagLen = 16;

class Sha256 {
 public:
  Sha256() { reset(); }
  void reset();
  void update(const void *data, size_t len);
  void finish(uint8_t out[kHashLen]);

 private:
  void block(const uint8_t *p);
  uint32_t h_[8];
  uint8_t buf_[64];
  uint64_t total_;
  size_t used_;
};

void sha256(const void *data, size_t len, uint8_t out[kHashLen]);

class HmacSha256 {
 public:
  void begin(const uint8_t *key, size_t keyLen);
  void update(const void *data, size_t len) { inner_.update(data, len); }
  void finish(uint8_t out[kHashLen]);

 private:
  Sha256 inner_;
  uint8_t opad_[64];
};

void hmacSha256(const uint8_t *key, size_t keyLen, const void *data, size_t len,
                uint8_t out[kHashLen]);

/** RFC 5869. */
void hkdfExtract(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen,
                 uint8_t prk[kHashLen]);
/** RFC 5869, outLen <= 255 * 32. `info` is a text label. */
void hkdfExpand(const uint8_t prk[kHashLen], const char *info, uint8_t *out, size_t outLen);

/** Compares in constant time. */
bool equal(const void *a, const void *b, size_t len);
/** Clears secrets; not optimized away. */
void wipe(void *p, size_t len);

/**
 * Random numbers: SHA-256 pool fed by the hardware generator, the timer and
 * any extra entropy (the LED noise, see PairTransport::entropy()).
 * On ESP32 with the radio off, esp_random() alone is not a full-entropy
 * source, hence the pool.
 */
void addEntropy(const void *data, size_t len);
void randomBytes(void *out, size_t len);

/** X25519 key pair from 32 random bytes (clamped inside). */
bool x25519Keypair(uint8_t priv[32], uint8_t pub[32]);
/** Shared secret. Returns false on failure or on an all-zero result (low-order point). */
bool x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t peerPub[32]);

bool gcmEncrypt(const uint8_t key[32], const uint8_t iv[kGcmIvLen], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out,
                uint8_t tag[kGcmTagLen]);
/** Returns false if the tag does not match; `out` is then cleared. */
bool gcmDecrypt(const uint8_t key[32], const uint8_t iv[kGcmIvLen], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out,
                const uint8_t tag[kGcmTagLen]);

// Backend hooks (CryptoMbed.cpp / CryptoPortable.cpp).
uint32_t hardwareRandom32();
uint32_t cycleCount();

}  // namespace crypto
}  // namespace securepair
