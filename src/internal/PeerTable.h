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
 * RAM copy of the peer records, and the key replacement rules
 * in docs/PROTOCOL.md, "What is saved". Every change is one atomic record write.
 */

#pragma once

#include <mutex>

#include "../PairStorage.h"

namespace securepair {

class PeerTable {
 public:
  static constexpr size_t kMaxSlots = 16;

  /** What saveCandidate() replaced, to undo it on an authenticated ABORT. */
  struct Undo {
    int slot = -1;
    bool hadRecord = false;
    PeerRecord prev = {};
  };

  explicit PeerTable(PairStorage &storage) : st_(storage) {}

  bool load(size_t maxPeers);
  size_t count() const;
  /** index-th stored peer (0..count()-1). */
  bool at(size_t index, PeerRecord &out) const;
  bool find(const PeerId &id, PeerRecord &out) const;
  bool contains(const PeerId &id) const;
  /** true if the peer is known or a free slot exists. */
  bool canStore(const PeerId &id) const;

  /**
   * Saves a newly agreed key.
   * @param peerSaved the peer is known to have saved it (its DONE was received):
   *                  the new key is used to send at once. Otherwise the old key
   *                  keeps being used to send and the new one is accepted only
   *                  on receive until promote().
   * @param peerSends the key the peer sends to us with, as it said in CONFIRM
   *                  or DONE; nullptr if it has none. If it is our pending new
   *                  key, that one is promoted first. If it is none of our keys
   *                  (the peer lost its records), the old record is dropped and
   *                  the new key starts from scratch, as in a first pairing.
   */
  bool saveCandidate(const PeerId &id, const uint8_t idPub[32], const uint8_t key[32],
                     const uint8_t keyId[kKeyIdLen], bool peerSaved, const uint8_t *peerSends,
                     uint32_t epoch, Undo &undo);
  /** The peer has saved `keyId` too: send with it from now on. */
  bool promote(const PeerId &id, const uint8_t keyId[kKeyIdLen]);
  /** Both sides use `keyId`: forget the previous key. */
  bool finalize(const PeerId &id, const uint8_t keyId[kKeyIdLen]);
  bool rollback(const Undo &undo);

  /** Records holding `keyId` as current or alternate key (at most `max`). */
  size_t withKeyId(const uint8_t keyId[kKeyIdLen], PeerRecord *out, size_t max) const;
  /** Persists a higher anti-replay epoch for the peer (once per peer reboot). */
  bool raiseRxEpoch(const PeerId &id, uint32_t epoch);

  bool forget(const PeerId &id);
  bool forgetAll();

 private:
  int slotOf(const PeerId &id) const;
  bool write(int slot, const PeerRecord &rec);

  PairStorage &st_;
  size_t slots_ = 0;
  PeerRecord rec_[kMaxSlots] = {};
  bool used_[kMaxSlots] = {};
  mutable std::mutex m_;
};

}  // namespace securepair
