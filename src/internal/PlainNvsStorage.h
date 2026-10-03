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
 * Records in clear in ESP32 NVS, for NvsPairStorage when the chip has no key.
 *
 * Keys "id" (identity), "epoch", "p00".."p15" (one blob per peer), each blob
 * with a CRC-32. One record is one nvs_set_blob + nvs_commit, which NVS keeps
 * atomic across power loss: either the old or the new value.
 *
 * If the epoch is lost (a damaged entry) while peers are saved, the peers are
 * erased too, before the epoch starts again: their keys never meet the same
 * epoch twice.
 */

#pragma once

#include <Preferences.h>

#include "../PairStorage.h"
#include "NvsNames.h"

namespace securepair {

class PlainNvsStorage : public PairStorage {
 public:
  PlainNvsStorage(const char *ns, size_t slots) : ns_(ns), slots_(slots) {}

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
  bool loadBlob(const char *key, void *data, size_t len);
  bool saveBlob(const char *key, const void *data, size_t len);

  Preferences prefs_;
  const char *ns_;
  size_t slots_;
  bool open_ = false;
};

}  // namespace securepair
