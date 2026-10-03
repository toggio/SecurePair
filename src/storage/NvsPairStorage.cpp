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
 */

#include "NvsPairStorage.h"

#ifdef ARDUINO
#include "HmacChipKey.h"
#endif

namespace securepair {

namespace {

// The chip's own key, on chips with an HMAC peripheral.
DeviceKey *chipKey() {
#if defined(ARDUINO) && SOC_HMAC_SUPPORTED
  static HmacChipKey key;
  return &key;
#else
  return nullptr;
#endif
}

size_t limitSlots(size_t slots) { return slots > nvs::kMaxSlots ? nvs::kMaxSlots : slots; }

}  // namespace

NvsPairStorage::NvsPairStorage(Encryption mode, const char *ns, size_t slots)
    : key_(nullptr),
      mode_(mode),
      slots_(limitSlots(slots)),
      plain_(ns, slots_),
      sealed_(ns, slots_) {}

NvsPairStorage::NvsPairStorage(DeviceKey &key, Encryption mode, const char *ns, size_t slots)
    : key_(&key),
      mode_(mode),
      slots_(limitSlots(slots)),
      plain_(ns, slots_),
      sealed_(ns, slots_) {}

bool NvsPairStorage::begin() {
  active_ = nullptr;
  DeviceKey *key = key_ ? key_ : chipKey();
  sealedMode_ = key && key->available();
  if (sealedMode_) {
    // What was saved in clear goes first, whatever happens next.
    sealed_.setKey(*key);
    if (!plain_.eraseAll() || !sealed_.begin()) return false;
    active_ = &sealed_;
    return true;
  }
  if (mode_ == Encryption::Required || !plain_.begin()) return false;
  active_ = &plain_;
  return true;
}

bool NvsPairStorage::loadIdentity(IdentityRecord &out) {
  return active_ && active_->loadIdentity(out);
}

bool NvsPairStorage::saveIdentity(const IdentityRecord &id) {
  return active_ && active_->saveIdentity(id);
}

bool NvsPairStorage::nextEpoch(uint32_t &epoch) { return active_ && active_->nextEpoch(epoch); }

bool NvsPairStorage::loadPeer(size_t slot, PeerRecord &out) {
  return active_ && active_->loadPeer(slot, out);
}

bool NvsPairStorage::savePeer(size_t slot, const PeerRecord &rec) {
  return active_ && active_->savePeer(slot, rec);
}

bool NvsPairStorage::erasePeer(size_t slot) { return active_ && active_->erasePeer(slot); }

bool NvsPairStorage::factoryReset() {
  const bool plainErased = plain_.eraseAll();
  return sealed_.eraseAll() && plainErased;
}

}  // namespace securepair
