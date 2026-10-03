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
 * Records sealed in ESP32 NVS, for NvsPairStorage when the chip has its key.
 *
 * Every record is sealed with AES-256-GCM (Seal.h) under a key derived from a
 * DeviceKey, normally the chip's eFuse key (HmacChipKey): a copy of the flash
 * shows no keys, and cannot be read on another board.
 *
 * Keys, next to those of PlainNvsStorage in the same namespace:
 *   "sid"           identity key pair and boot epoch, in one record
 *   "s00".."s15"    one peer per slot, bound to the identity
 *
 * Someone who can write the flash can still delete records, but that only
 * makes the board forget. The epoch cannot be removed without the identity,
 * and without the identity the old peer records no longer open: no saved key
 * is used again with an epoch that starts over.
 */

#pragma once

#include <Preferences.h>

#include "../DeviceKey.h"
#include "../PairStorage.h"
#include "NvsNames.h"
#include "Seal.h"

namespace securepair {

class SealedNvsStorage : public PairStorage {
 public:
  SealedNvsStorage(const char *ns, size_t slots) : ns_(ns), slots_(slots) {}
  ~SealedNvsStorage();

  /** The key the storage key comes from. Needed before begin(). */
  void setKey(DeviceKey &key) { key_ = &key; }

  /**
   * Fails without a key, or if the saved identity does not open (damaged, or
   * written by another chip). SecurePair then refuses to pair, instead of
   * starting over with a new identity.
   */
  bool begin() override;
  bool loadIdentity(IdentityRecord &out) override;
  bool saveIdentity(const IdentityRecord &id) override;
  bool nextEpoch(uint32_t &epoch) override;
  size_t capacity() const override { return slots_; }
  bool loadPeer(size_t slot, PeerRecord &out) override;
  bool savePeer(size_t slot, const PeerRecord &rec) override;
  bool erasePeer(size_t slot) override;

  /** Removes identity, epoch and peers in this format only, even before begin(). */
  bool eraseAll();

 private:
  struct IdRecord {
    IdentityRecord id;
    uint32_t epoch;
  };
  static constexpr size_t kMaxRecord =
      sizeof(PeerRecord) > sizeof(IdRecord) ? sizeof(PeerRecord) : sizeof(IdRecord);

  enum class Read { Ok, Missing, Damaged };

  bool openNamespace();
  Read read(const char *name, bool bound, void *data, size_t len);
  bool write(const char *name, bool bound, const void *data, size_t len);
  size_t context(const char *name, bool bound, uint8_t *out) const;

  DeviceKey *key_ = nullptr;
  Preferences prefs_;
  const char *ns_;
  size_t slots_;
  bool open_ = false;
  bool ready_ = false;            // begin() succeeded
  bool hasId_ = false;
  uint8_t idPub_[kKeyLen] = {};   // the identity the peer records are bound to
  seal::Keys keys_ = {};
};

}  // namespace securepair
