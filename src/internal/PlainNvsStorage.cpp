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
 * Records in clear in ESP32 NVS.
 */

#include "PlainNvsStorage.h"

#include <string.h>

#include "Crypto.h"

namespace securepair {

namespace {

uint32_t crc32(const uint8_t *p, size_t n) {
  uint32_t c = 0xFFFFFFFF;
  while (n--) {
    c ^= *p++;
    for (int i = 0; i < 8; ++i) c = (c >> 1) ^ (0xEDB88320 & (0u - (c & 1)));
  }
  return ~c;
}

}  // namespace

bool PlainNvsStorage::begin() {
  if (!open_) open_ = prefs_.begin(ns_, false);
  return open_;
}

// Blob = data + CRC-32, written in one call.
bool PlainNvsStorage::loadBlob(const char *key, void *data, size_t len) {
  uint8_t buf[sizeof(PeerRecord) + 4];
  if (len + 4 > sizeof(buf) || prefs_.getBytesLength(key) != len + 4) return false;
  if (prefs_.getBytes(key, buf, len + 4) != len + 4) return false;
  uint32_t stored;
  memcpy(&stored, buf + len, 4);
  const bool ok = crc32(buf, len) == stored;
  if (ok) memcpy(data, buf, len);
  crypto::wipe(buf, sizeof(buf));
  return ok;
}

bool PlainNvsStorage::saveBlob(const char *key, const void *data, size_t len) {
  uint8_t buf[sizeof(PeerRecord) + 4];
  if (len + 4 > sizeof(buf)) return false;
  memcpy(buf, data, len);
  const uint32_t crc = crc32(buf, len);
  memcpy(buf + len, &crc, 4);
  const bool ok = prefs_.putBytes(key, buf, len + 4) == len + 4;
  crypto::wipe(buf, sizeof(buf));
  return ok;
}

bool PlainNvsStorage::loadIdentity(IdentityRecord &out) {
  return loadBlob("id", &out, sizeof(out));
}

bool PlainNvsStorage::saveIdentity(const IdentityRecord &id) {
  return saveBlob("id", &id, sizeof(id));
}

bool PlainNvsStorage::nextEpoch(uint32_t &epoch) {
  // Without the saved epoch, a saved key could meet an epoch it has already
  // used: the peers are erased first, from every slot, even those beyond
  // slots_. After a power cut halfway, the next start finishes the job.
  if (!prefs_.isKey("epoch")) {
    for (size_t i = 0; i < nvs::kMaxSlots; ++i) {
      char key[4];
      nvs::slotName('p', i, key);
      if (prefs_.isKey(key) && !prefs_.remove(key)) return false;
    }
  }
  const uint32_t e = prefs_.getUInt("epoch", 0) + 1;
  if (prefs_.putUInt("epoch", e) != sizeof(uint32_t)) return false;
  epoch = e;
  return true;
}

bool PlainNvsStorage::loadPeer(size_t slot, PeerRecord &out) {
  if (slot >= slots_) return false;
  char key[4];
  nvs::slotName('p', slot, key);
  return loadBlob(key, &out, sizeof(out));
}

bool PlainNvsStorage::savePeer(size_t slot, const PeerRecord &rec) {
  if (slot >= slots_) return false;
  char key[4];
  nvs::slotName('p', slot, key);
  return saveBlob(key, &rec, sizeof(rec));
}

bool PlainNvsStorage::erasePeer(size_t slot) {
  if (slot >= slots_) return false;
  char key[4];
  nvs::slotName('p', slot, key);
  return !prefs_.isKey(key) || prefs_.remove(key);
}

bool PlainNvsStorage::eraseAll() {
  if (!begin()) return false;
  bool ok = true;
  const char *const named[] = {"id", "epoch"};
  for (const char *key : named)
    if (prefs_.isKey(key) && !prefs_.remove(key)) ok = false;
  for (size_t i = 0; i < nvs::kMaxSlots; ++i) {
    char key[4];
    nvs::slotName('p', i, key);
    if (prefs_.isKey(key) && !prefs_.remove(key)) ok = false;
  }
  return ok;
}

}  // namespace securepair
