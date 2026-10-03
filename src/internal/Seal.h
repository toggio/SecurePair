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
 * Records sealed for storage with AES-256-GCM.
 *
 *   blob = version (1) | nonce (12) | ciphertext | tag (16)
 *
 * The nonce is an HMAC of the record, its context and 16 random bytes: two
 * different records share a nonce only if two 96-bit HMAC outputs collide,
 * even if the random bytes repeat.
 * The context (namespace, record name, ...) is authenticated but not stored,
 * so a blob opens only where it was written.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace securepair {
namespace seal {

constexpr uint8_t kVersion = 1;
constexpr size_t kOverhead = 1 + 12 + 16;
constexpr size_t kMaxContext = 64;

struct Keys {
  uint8_t enc[32];     // AES-256-GCM
  uint8_t nonce[32];   // HMAC that makes the nonces
};

/** Both keys from one 32-byte secret (HKDF). */
void deriveKeys(const uint8_t secret[32], Keys &out);

/** Writes len + kOverhead bytes to `out`. False if the context is too long. */
bool seal(const Keys &k, const uint8_t *context, size_t contextLen, const void *in, size_t len,
          uint8_t *out);

/**
 * Opens a blob of len + kOverhead bytes into `out`. False if the blob was
 * changed, or sealed with another key or for another context; `out` is then
 * cleared.
 */
bool open(const Keys &k, const uint8_t *context, size_t contextLen, const uint8_t *blob,
          size_t blobLen, void *out, size_t len);

}  // namespace seal
}  // namespace securepair
