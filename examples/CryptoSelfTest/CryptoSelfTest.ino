/*
 * SecurePair - CryptoSelfTest
 *
 * Checks the cryptography on the board (Mbed TLS X25519 and AES-256-GCM, plus
 * SHA-256, HMAC and HKDF) against reference values computed with the Python
 * "cryptography" package (vectors.h, from extras/test/gen_vectors.py).
 * Needs no wiring. Open the Serial Monitor at 115200.
 */

#include <SecurePair.h>
#include <internal/Crypto.h>

#include "vectors.h"

using namespace securepair;

int checks = 0, failures = 0;

void check(bool ok, const char *what) {
  ++checks;
  if (!ok) {
    ++failures;
    Serial.printf("FAIL %s\n", what);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  uint8_t out[80];

  for (const XVec &v : kX25519) {
    check(crypto::x25519(out, v.priv, v.peer) && memcmp(out, v.shared, 32) == 0, "x25519");
  }
  const uint8_t zero[32] = {};
  check(!crypto::x25519(out, kX25519[0].priv, zero), "x25519 low order");

  for (const GVec &v : kGcm) {
    uint8_t ct[70], tag[16], pt[70];
    check(crypto::gcmEncrypt(v.key, v.iv, v.aad, v.aadLen, v.pt, v.len, ct, tag) &&
              memcmp(ct, v.ct, v.len) == 0 && memcmp(tag, v.tag, 16) == 0,
          "gcm encrypt");
    check(crypto::gcmDecrypt(v.key, v.iv, v.aad, v.aadLen, v.ct, v.len, pt, v.tag) &&
              memcmp(pt, v.pt, v.len) == 0,
          "gcm decrypt");
    uint8_t bad[16];
    memcpy(bad, v.tag, 16);
    bad[0] ^= 1;
    check(!crypto::gcmDecrypt(v.key, v.iv, v.aad, v.aadLen, v.ct, v.len, pt, bad), "gcm bad tag");
  }

  const size_t lens[3] = {0, 55, 200};
  for (int i = 0; i < 3; ++i) {
    crypto::sha256(kShaMsg, lens[i], out);
    check(memcmp(out, kShaDigest[i], 32) == 0, "sha256");
  }
  crypto::hmacSha256(kHmacKey, 20, kShaMsg, 200, out);
  check(memcmp(out, kHmac[0], 32) == 0, "hmac");
  uint8_t prk[32];
  crypto::hkdfExtract(kHkdfSalt, 32, kHkdfIkm, 64, prk);
  crypto::hkdfExpand(prk, "link test", out, 80);
  check(memcmp(prk, kHkdfPrk, 32) == 0 && memcmp(out, kHkdfOkm, 80) == 0, "hkdf");

  // Timing of the operations a pairing needs.
  uint8_t priv[32], pub[32];
  uint32_t t = micros();
  check(crypto::x25519Keypair(priv, pub), "keypair");
  const uint32_t keygenUs = micros() - t;
  t = micros();
  check(crypto::x25519(out, priv, kX25519[1].peer), "shared");
  const uint32_t dhUs = micros() - t;

  Serial.printf("SecurePair %s crypto self-test: %d checks, %d failures\n", SECUREPAIR_VERSION,
                checks, failures);
  Serial.printf("X25519 key pair %u us, shared secret %u us\n", (unsigned)keygenUs, (unsigned)dhUs);
}

void loop() {}
