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
 * Protocol version 5: messages and key schedule.
 */

#include "Protocol.h"

#include <string.h>

namespace securepair {
namespace proto {

using namespace crypto;

size_t header(uint8_t *out, MsgType type, const uint8_t xid[kXidLen]) {
  out[0] = kProtocolVersion;
  out[1] = type;
  memcpy(out + 2, xid, kXidLen);
  return kHeaderLen;
}

bool parseHeader(const uint8_t *msg, size_t len, MsgType &type) {
  if (len < kHeaderLen || msg[0] != kProtocolVersion) return false;
  type = static_cast<MsgType>(msg[1]);
  switch (type) {
    case kOffer: return len == kOfferLen;
    case kReveal: return len == kRevealLen;
    case kIdent: return len == kIdentLen;
    case kSasSync: return len == kSasSyncLen;
    case kConfirm: return len == kConfirmLen;
    case kDone: return len == kDoneLen;
    case kAbort: return len == kAbortLen || len == kAbortAuthLen;
  }
  return false;
}

void commitment(const uint8_t xid[kXidLen], const uint8_t ePub[32], const uint8_t nonce[kNonceLen],
                uint8_t out[32]) {
  Sha256 s;
  s.update("SecurePair/commit", 17);
  s.update(xid, kXidLen);
  s.update(ePub, 32);
  s.update(nonce, kNonceLen);
  s.finish(out);
}

void peerIdFromPub(const uint8_t idPub[32], PeerId &out) {
  uint8_t h[32];
  Sha256 s;
  s.update("SecurePair/id", 13);
  s.update(idPub, 32);
  s.finish(h);
  memcpy(out.b, h, kPeerIdLen);
}

bool deriveStage1(const uint8_t xid[kXidLen], const uint8_t commit[32], const uint8_t selfEPriv[32],
                  const uint8_t selfEPub[32], const uint8_t selfNonce[kNonceLen],
                  const uint8_t peerEPub[32], const uint8_t peerNonce[kNonceLen], Stage1 &out) {
  const int cmp = memcmp(selfEPub, peerEPub, 32);
  if (cmp == 0) return false;
  out.selfIsLo = cmp < 0;
  if (!x25519(out.ee, selfEPriv, peerEPub)) return false;

  const uint8_t *loPub = out.selfIsLo ? selfEPub : peerEPub;
  const uint8_t *loN = out.selfIsLo ? selfNonce : peerNonce;
  const uint8_t *hiPub = out.selfIsLo ? peerEPub : selfEPub;
  const uint8_t *hiN = out.selfIsLo ? peerNonce : selfNonce;

  const uint8_t suite = kSuite;
  Sha256 s;
  s.update("SecurePair/5", 12);
  s.update(&suite, 1);
  s.update(xid, kXidLen);
  s.update(commit, 32);
  s.update(loPub, 32);
  s.update(loN, kNonceLen);
  s.update(hiPub, 32);
  s.update(hiN, kNonceLen);
  s.finish(out.th1);

  uint8_t prk[32];
  hkdfExtract(out.th1, 32, out.ee, 32, prk);
  hkdfExpand(prk, out.selfIsLo ? "hs lo" : "hs hi", out.hsSelf, 32);
  hkdfExpand(prk, out.selfIsLo ? "hs hi" : "hs lo", out.hsPeer, 32);
  // The SAS depends only on committed values (prk1), never on the identities:
  // those travel later and could otherwise be brute-forced by a man in the middle.
  uint8_t sas[4];
  hkdfExpand(prk, "sas", sas, sizeof(sas));
  out.sas.value = ((uint32_t)sas[0] << 12 | (uint32_t)sas[1] << 4 | sas[2] >> 4) &
                  ((1u << kCodeBits) - 1);
  wipe(prk, sizeof(prk));
  return true;
}

bool deriveStage2(const Stage1 &s1, const uint8_t selfIdPriv[32], const uint8_t selfIdPub[32],
                  const uint8_t peerIdPub[32], Stage2 &out) {
  if (memcmp(selfIdPub, peerIdPub, 32) == 0) return false;
  uint8_t ss[32];
  if (!x25519(ss, selfIdPriv, peerIdPub)) return false;

  // Identities ordered like the ephemeral keys (lo side first).
  Sha256 s;
  s.update(s1.th1, 32);
  s.update(s1.selfIsLo ? selfIdPub : peerIdPub, 32);
  s.update(s1.selfIsLo ? peerIdPub : selfIdPub, 32);
  s.finish(out.th2);

  uint8_t ikm[64];
  memcpy(ikm, s1.ee, 32);
  memcpy(ikm + 32, ss, 32);
  uint8_t prk[32];
  hkdfExtract(out.th2, 32, ikm, sizeof(ikm), prk);
  hkdfExpand(prk, "link", out.linkKey, 32);
  hkdfExpand(prk, "kid", out.keyId, kKeyIdLen);
  hkdfExpand(prk, s1.selfIsLo ? "cf lo" : "cf hi", out.cfSelf, 32);
  hkdfExpand(prk, s1.selfIsLo ? "cf hi" : "cf lo", out.cfPeer, 32);
  wipe(ss, sizeof(ss));
  wipe(ikm, sizeof(ikm));
  wipe(prk, sizeof(prk));
  return true;
}

void mac(const uint8_t key[32], const char *label, const uint8_t *hdr, const uint8_t th2[32],
         const uint8_t *extra, size_t extraLen, uint8_t *out, size_t outLen) {
  uint8_t full[32];
  HmacSha256 h;
  h.begin(key, 32);
  h.update(label, strlen(label));
  h.update(hdr, kHeaderLen);
  h.update(th2, 32);
  if (extraLen) h.update(extra, extraLen);
  h.finish(full);
  memcpy(out, full, outLen);
  wipe(full, sizeof(full));
}

void sealIdent(const uint8_t hsKey[32], const uint8_t *hdr, const uint8_t idPub[32],
               uint8_t out[32 + kGcmTagLen]) {
  const uint8_t iv[kGcmIvLen] = {};
  gcmEncrypt(hsKey, iv, hdr, kHeaderLen, idPub, 32, out, out + 32);
}

bool openIdent(const uint8_t hsKey[32], const uint8_t *hdr, const uint8_t *in,
               uint8_t idPub[32]) {
  const uint8_t iv[kGcmIvLen] = {};
  return gcmDecrypt(hsKey, iv, hdr, kHeaderLen, in, 32, idPub, in + 32);
}

void directionalKey(const uint8_t linkKey[32], const PeerId &from, const PeerId &to,
                    uint8_t out[32]) {
  // Label built as text so hkdfExpand() can take it: "dir" + hex ids.
  char info[4 + 4 * kPeerIdLen + 1] = "dir ";
  static const char hex[] = "0123456789abcdef";
  char *p = info + 4;
  for (size_t i = 0; i < kPeerIdLen; ++i) {
    *p++ = hex[from.b[i] >> 4];
    *p++ = hex[from.b[i] & 15];
  }
  for (size_t i = 0; i < kPeerIdLen; ++i) {
    *p++ = hex[to.b[i] >> 4];
    *p++ = hex[to.b[i] & 15];
  }
  *p = 0;
  hkdfExpand(linkKey, info, out, 32);
}

}  // namespace proto
}  // namespace securepair
