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
 * Records sealed for storage.
 */

#include "Seal.h"

#include <string.h>

#include "Crypto.h"

namespace securepair {
namespace seal {

static_assert(kOverhead == 1 + crypto::kGcmIvLen + crypto::kGcmTagLen, "blob layout");

namespace {

// The version byte is authenticated along with the context.
size_t makeAad(const uint8_t *context, size_t contextLen, uint8_t out[1 + kMaxContext]) {
  out[0] = kVersion;
  memcpy(out + 1, context, contextLen);
  return 1 + contextLen;
}

void addLength(crypto::HmacSha256 &h, size_t n) {
  const uint8_t b[2] = {(uint8_t)(n >> 8), (uint8_t)n};
  h.update(b, sizeof(b));
}

}  // namespace

void deriveKeys(const uint8_t secret[32], Keys &out) {
  crypto::hkdfExpand(secret, "SecurePair seal key", out.enc, sizeof(out.enc));
  crypto::hkdfExpand(secret, "SecurePair seal nonce", out.nonce, sizeof(out.nonce));
}

bool seal(const Keys &k, const uint8_t *context, size_t contextLen, const void *in, size_t len,
          uint8_t *out) {
  if (contextLen > kMaxContext) return false;

  // The lengths keep context and record apart inside the HMAC.
  uint8_t random[16], mac[crypto::kHashLen];
  crypto::randomBytes(random, sizeof(random));
  crypto::HmacSha256 h;
  h.begin(k.nonce, sizeof(k.nonce));
  addLength(h, contextLen);
  h.update(context, contextLen);
  addLength(h, len);
  h.update(in, len);
  h.update(random, sizeof(random));
  h.finish(mac);
  crypto::wipe(&h, sizeof(h));

  uint8_t aad[1 + kMaxContext];
  const size_t aadLen = makeAad(context, contextLen, aad);
  uint8_t *iv = out + 1;
  uint8_t *ct = iv + crypto::kGcmIvLen;
  out[0] = kVersion;
  memcpy(iv, mac, crypto::kGcmIvLen);
  crypto::wipe(mac, sizeof(mac));
  return crypto::gcmEncrypt(k.enc, iv, aad, aadLen, static_cast<const uint8_t *>(in), len, ct,
                            ct + len);
}

bool open(const Keys &k, const uint8_t *context, size_t contextLen, const uint8_t *blob,
          size_t blobLen, void *out, size_t len) {
  if (contextLen > kMaxContext || blobLen != len + kOverhead || blob[0] != kVersion) {
    crypto::wipe(out, len);
    return false;
  }
  uint8_t aad[1 + kMaxContext];
  const size_t aadLen = makeAad(context, contextLen, aad);
  const uint8_t *iv = blob + 1;
  const uint8_t *ct = iv + crypto::kGcmIvLen;
  return crypto::gcmDecrypt(k.enc, iv, aad, aadLen, ct, len, static_cast<uint8_t *>(out),
                            ct + len);
}

}  // namespace seal
}  // namespace securepair
