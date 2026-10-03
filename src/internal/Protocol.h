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
 * Protocol version 5: messages and key schedule (docs/PROTOCOL.md).
 * No I/O here: everything is testable on the PC.
 */

#pragma once

#include "../PairTypes.h"
#include "Crypto.h"

namespace securepair {
namespace proto {

enum MsgType : uint8_t {
  kOffer = 0x01,
  kReveal = 0x02,
  kIdent = 0x03,
  kSasSync = 0x04,
  kConfirm = 0x05,
  kDone = 0x06,
  kAbort = 0x07,
};

enum AbortReason : uint8_t {
  kAbortUser = 1,
  kAbortTimeout = 2,
  kAbortStorageFull = 3,
  kAbortProtocol = 4,
};

constexpr size_t kHeaderLen = 2 + kXidLen;   // ver, type, xid
constexpr size_t kNonceLen = 16;
constexpr size_t kMac16 = 16;
constexpr size_t kMac8 = 8;

constexpr size_t kOfferLen = kHeaderLen + 32;
constexpr size_t kRevealLen = kHeaderLen + 32 + kNonceLen;
constexpr size_t kIdentLen = kHeaderLen + 32 + crypto::kGcmTagLen;
constexpr size_t kSasSyncLen = kHeaderLen + kMac8;
// CONFIRM and DONE carry the key the sender uses for the receiver (zeros: none).
constexpr size_t kConfirmLen = kHeaderLen + kKeyIdLen + kMac16;
constexpr size_t kDoneLen = kHeaderLen + kKeyIdLen + kMac16;
constexpr size_t kAbortLen = kHeaderLen + 1;
constexpr size_t kAbortAuthLen = kHeaderLen + 1 + kMac16;
static_assert(kRevealLen <= kMaxPairMessage && kIdentLen <= kMaxPairMessage, "messages too long");

/** Writes the header; returns kHeaderLen. */
size_t header(uint8_t *out, MsgType type, const uint8_t xid[kXidLen]);

/** true if `msg` has our version, the given length for its type and (if xid) the xid. */
bool parseHeader(const uint8_t *msg, size_t len, MsgType &type);

/** C = SHA-256("SecurePair/commit" || xid || e_pub || n). */
void commitment(const uint8_t xid[kXidLen], const uint8_t ePub[32], const uint8_t nonce[kNonceLen],
                uint8_t out[32]);

void peerIdFromPub(const uint8_t idPub[32], PeerId &out);

/** Keys after the ephemeral exchange. `lo` is the side with the smaller e_pub. */
struct Stage1 {
  uint8_t th1[32];
  uint8_t ee[32];
  uint8_t hsSelf[32], hsPeer[32];   // IDENT keys
  PairCode sas;
  bool selfIsLo;
};

/** Keys after the identities. */
struct Stage2 {
  uint8_t th2[32];
  uint8_t linkKey[32];
  uint8_t keyId[kKeyIdLen];
  uint8_t cfSelf[32], cfPeer[32];   // MAC keys for SAS_SYNC, CONFIRM, DONE, ABORT
};

/**
 * @param commit the offerer's commitment
 * @return false if the ephemeral keys are equal (reflection) or ee is zero
 */
bool deriveStage1(const uint8_t xid[kXidLen], const uint8_t commit[32], const uint8_t selfEPriv[32],
                  const uint8_t selfEPub[32], const uint8_t selfNonce[kNonceLen],
                  const uint8_t peerEPub[32], const uint8_t peerNonce[kNonceLen], Stage1 &out);

/** @return false if the identities are equal or ss is zero. */
bool deriveStage2(const Stage1 &s1, const uint8_t selfIdPriv[32], const uint8_t selfIdPub[32],
                  const uint8_t peerIdPub[32], Stage2 &out);

/** Truncated HMAC over label || message header || th2 || extra. */
void mac(const uint8_t key[32], const char *label, const uint8_t *hdr, const uint8_t th2[32],
         const uint8_t *extra, size_t extraLen, uint8_t *out, size_t outLen);

/** IDENT payload: AES-256-GCM of the identity key, nonce 0 (one message per key). */
void sealIdent(const uint8_t hsKey[32], const uint8_t *hdr, const uint8_t idPub[32],
               uint8_t out[32 + crypto::kGcmTagLen]);
bool openIdent(const uint8_t hsKey[32], const uint8_t *hdr, const uint8_t *in,
               uint8_t idPub[32]);

/** Per-direction data key (for SecureLink): HKDF-Expand(linkKey, "dir" || from || to). */
void directionalKey(const uint8_t linkKey[32], const PeerId &from, const PeerId &to,
                    uint8_t out[32]);

}  // namespace proto
}  // namespace securepair
