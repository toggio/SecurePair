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
 * X25519 and AES-256-GCM through Mbed TLS (ESP32).
 */

#if defined(ESP_PLATFORM) && !defined(SECUREPAIR_PORTABLE_CRYPTO)

#include <esp_cpu.h>
#include <esp_random.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <string.h>

#include "Crypto.h"

namespace securepair {
namespace crypto {

uint32_t hardwareRandom32() { return esp_random(); }

uint32_t cycleCount() { return (uint32_t)esp_cpu_get_cycle_count(); }

namespace {

int rng(void *, unsigned char *out, size_t len) {
  randomBytes(out, len);
  return 0;
}

}  // namespace

bool x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t peerPub[32]) {
  uint8_t k[32];
  memcpy(k, priv, 32);
  k[0] &= 248;  // Mbed TLS only accepts clamped scalars; X25519 clamps anyway
  k[31] &= 127;
  k[31] |= 64;

  mbedtls_ecp_group grp;
  mbedtls_ecp_point q;
  mbedtls_mpi d, z;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);

  bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
            mbedtls_mpi_read_binary_le(&d, k, 32) == 0 &&
            mbedtls_ecp_point_read_binary(&grp, &q, peerPub, 32) == 0 &&
            mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, rng, nullptr) == 0 &&
            mbedtls_mpi_write_binary_le(&z, out, 32) == 0;

  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&q);
  mbedtls_ecp_group_free(&grp);
  wipe(k, sizeof(k));

  if (!ok) {
    wipe(out, 32);
    return false;
  }
  uint8_t acc = 0;
  for (int i = 0; i < 32; ++i) acc |= out[i];
  return acc != 0;
}

bool gcmEncrypt(const uint8_t key[32], const uint8_t iv[kGcmIvLen], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out,
                uint8_t tag[kGcmTagLen]) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  const bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
                  mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, iv, kGcmIvLen, aad,
                                            aadLen, in, out, kGcmTagLen, tag) == 0;
  mbedtls_gcm_free(&ctx);
  return ok;
}

bool gcmDecrypt(const uint8_t key[32], const uint8_t iv[kGcmIvLen], const uint8_t *aad,
                size_t aadLen, const uint8_t *in, size_t len, uint8_t *out,
                const uint8_t tag[kGcmTagLen]) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  const bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
                  mbedtls_gcm_auth_decrypt(&ctx, len, iv, kGcmIvLen, aad, aadLen, tag,
                                           kGcmTagLen, in, out) == 0;
  mbedtls_gcm_free(&ctx);
  if (!ok) wipe(out, len);
  return ok;
}

}  // namespace crypto
}  // namespace securepair

#endif
