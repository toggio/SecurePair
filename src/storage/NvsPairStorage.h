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
 * Storage in ESP32 NVS, encrypted once the chip has its own key.
 *
 *   NvsPairStorage storage;                         // encrypted if the chip has its key
 *   NvsPairStorage storage(Encryption::Required);   // encrypted or nothing
 *
 * With the chip's key, written once by the ChipKeySetup example, every record
 * is sealed with AES-256-GCM under a key derived from it: a copy of the flash
 * shows no keys, and does not open on another board. Without it, the records
 * are saved in clear, each with a CRC-32. The original ESP32 has no HMAC
 * peripheral, so no chip key: there they are always in clear.
 *
 * Once the chip has its key, whatever was saved in clear is erased, never
 * imported: someone able to write the flash could have put it there. A board
 * paired before its key was written starts over.
 */

#pragma once

#include "../DeviceKey.h"
#include "../internal/PlainNvsStorage.h"
#include "../internal/SealedNvsStorage.h"

namespace securepair {

enum class Encryption : uint8_t {
  IfAvailable,   // sealed if the key is there, in clear otherwise
  Required,      // sealed or nothing: without the key begin() fails
};

class NvsPairStorage : public PairStorage {
 public:
  static constexpr size_t kMaxSlots = nvs::kMaxSlots;

  /** With the chip's own key (HmacChipKey), where the chip has an HMAC peripheral. */
  explicit NvsPairStorage(Encryption mode = Encryption::IfAvailable,
                          const char *ns = "securepair", size_t slots = 8);

  /** With another key, a secure element for instance. */
  explicit NvsPairStorage(DeviceKey &key, Encryption mode = Encryption::IfAvailable,
                          const char *ns = "securepair", size_t slots = 8);

  /**
   * Seals the records if the key is there, keeps them in clear if it is not
   * (or fails, with Encryption::Required). With the key, it also fails if the
   * saved identity does not open (damaged, or written by another chip): that
   * never makes it fall back to clear.
   */
  bool begin() override;

  /** After begin(): whether the records are sealed. */
  bool encrypted() const { return sealedMode_; }

  bool loadIdentity(IdentityRecord &out) override;
  bool saveIdentity(const IdentityRecord &id) override;
  bool nextEpoch(uint32_t &epoch) override;
  size_t capacity() const override { return slots_; }
  bool loadPeer(size_t slot, PeerRecord &out) override;
  bool savePeer(size_t slot, const PeerRecord &rec) override;
  bool erasePeer(size_t slot) override;

  /**
   * Erases identity, epoch and peers, in clear and sealed, even when begin()
   * fails: the board becomes a new device.
   */
  bool factoryReset();

 private:
  DeviceKey *key_;   // nullptr: the chip's own key, if it has one
  Encryption mode_;
  size_t slots_;
  PlainNvsStorage plain_;
  SealedNvsStorage sealed_;
  PairStorage *active_ = nullptr;   // the one in use, after a successful begin()
  bool sealedMode_ = false;
};

}  // namespace securepair
