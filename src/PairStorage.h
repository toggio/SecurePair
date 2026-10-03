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
 * Persistent identity, boot epoch and peer records.
 */

#pragma once

#include "PairTypes.h"

namespace securepair {

struct IdentityRecord {
  uint8_t priv[kKeyLen];
  uint8_t pub[kKeyLen];
};

/**
 * One paired peer. Stored as a single blob, so replacing it is one atomic write.
 *
 * `key` is used to send and receive. `altKey` (when kHasAlt is set) is only
 * accepted when receiving, while a re-pairing completes (docs/PROTOCOL.md,
 * "What is saved"):
 *   kAltIsNew set:   saved before knowing that the peer saved too, so the old
 *                    key still sends and the new one is the alternate
 *   kAltIsNew clear: the new key sends, the old one is the alternate
 */
struct PeerRecord {
  enum Flags : uint8_t {
    kHasAlt = 0x01,
    kAltIsNew = 0x02,     // otherwise the alternate key is the old one
    kUnproven = 0x04,     // first pairing, DONE from the peer not received yet
  };

  uint8_t format;                 // record layout version
  uint8_t flags;
  PeerId id;
  uint8_t idPub[kKeyLen];         // the real identity; id is only an index
  uint8_t key[kKeyLen];
  uint8_t keyId[kKeyIdLen];
  uint8_t altKey[kKeyLen];
  uint8_t altKeyId[kKeyIdLen];
  uint32_t rxEpoch;               // highest epoch accepted from this peer (anti-replay)
  uint32_t pairedEpoch;           // our epoch when it was paired (informative)
};

class PairStorage {
 public:
  virtual ~PairStorage() {}

  virtual bool begin() = 0;

  /** @return false if there is no valid identity yet. */
  virtual bool loadIdentity(IdentityRecord &out) = 0;
  virtual bool saveIdentity(const IdentityRecord &id) = 0;

  /**
   * Increments the boot epoch and makes it persistent before returning. If it
   * fails, SecurePair::begin() fails and nothing is sent: a reused nonce could
   * not be undone. If the saved epoch was lost, the saved peers must be lost
   * with it before it starts again.
   */
  virtual bool nextEpoch(uint32_t &epoch) = 0;

  virtual size_t capacity() const = 0;

  /** @return false if the slot is empty or its CRC does not match. */
  virtual bool loadPeer(size_t slot, PeerRecord &out) = 0;

  /** Atomic: after a power loss the slot holds either the old or the new record. */
  virtual bool savePeer(size_t slot, const PeerRecord &rec) = 0;
  virtual bool erasePeer(size_t slot) = 0;
};

}  // namespace securepair
