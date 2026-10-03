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
 * Storage in RAM, for tests. Nothing survives a reset: identity, epoch and
 * peers are lost, so every start needs a new pairing.
 */

#pragma once

#include "../PairStorage.h"

namespace securepair {

class MemoryPairStorage : public PairStorage {
 public:
  static constexpr size_t kSlots = 8;

  bool begin() override { return true; }

  bool loadIdentity(IdentityRecord &out) override {
    if (!hasId_) return false;
    out = id_;
    return true;
  }
  bool saveIdentity(const IdentityRecord &id) override {
    if (failWrites) return false;
    id_ = id;
    hasId_ = true;
    return true;
  }

  bool nextEpoch(uint32_t &epoch) override {
    if (failWrites) return false;
    epoch = ++epoch_;
    return true;
  }

  size_t capacity() const override { return kSlots; }

  bool loadPeer(size_t slot, PeerRecord &out) override {
    if (slot >= kSlots || !used_[slot]) return false;
    out = rec_[slot];
    return true;
  }
  bool savePeer(size_t slot, const PeerRecord &rec) override {
    if (slot >= kSlots || failWrites) return false;
    rec_[slot] = rec;
    used_[slot] = true;
    ++writes;
    return true;
  }
  bool erasePeer(size_t slot) override {
    if (slot >= kSlots || failWrites) return false;
    used_[slot] = false;
    ++writes;
    return true;
  }

  bool failWrites = false;   // test hook
  unsigned writes = 0;

 private:
  IdentityRecord id_ = {};
  bool hasId_ = false;
  uint32_t epoch_ = 0;
  PeerRecord rec_[kSlots] = {};
  bool used_[kSlots] = {};
};

}  // namespace securepair
