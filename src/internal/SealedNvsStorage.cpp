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
 * Records sealed in ESP32 NVS.
 */

#include "SealedNvsStorage.h"

#include <string.h>

#include "Crypto.h"

namespace securepair {

namespace {

const char kIdName[] = "sid";

// Copies a name with its final 0. NVS names have at most 15 characters.
size_t addName(uint8_t *out, const char *name) {
  const size_t len = strnlen(name, 15);
  memcpy(out, name, len);
  out[len] = 0;
  return len + 1;
}

}  // namespace

SealedNvsStorage::~SealedNvsStorage() { crypto::wipe(&keys_, sizeof(keys_)); }

bool SealedNvsStorage::openNamespace() {
  if (!open_) open_ = prefs_.begin(ns_, false);
  return open_;
}

bool SealedNvsStorage::begin() {
  ready_ = hasId_ = false;
  if (!openNamespace()) return false;

  static const char kLabel[] = "SecurePair storage";
  uint8_t secret[32];
  if (!key_ || !key_->derive(kLabel, sizeof(kLabel) - 1, secret)) return false;
  seal::deriveKeys(secret, keys_);
  crypto::wipe(secret, sizeof(secret));

  IdRecord r;
  const Read got = read(kIdName, false, &r, sizeof(r));
  if (got == Read::Ok) memcpy(idPub_, r.id.pub, kKeyLen);
  crypto::wipe(&r, sizeof(r));
  if (got == Read::Damaged) return false;
  hasId_ = got == Read::Ok;
  ready_ = true;
  return true;
}

bool SealedNvsStorage::loadIdentity(IdentityRecord &out) {
  IdRecord r;
  const bool ok = ready_ && read(kIdName, false, &r, sizeof(r)) == Read::Ok;
  if (ok) out = r.id;
  crypto::wipe(&r, sizeof(r));
  return ok;
}

bool SealedNvsStorage::saveIdentity(const IdentityRecord &id) {
  if (!ready_) return false;
  // A replaced identity passes its epoch on: epochs never go back.
  IdRecord r;
  if (read(kIdName, false, &r, sizeof(r)) != Read::Ok) r.epoch = 0;
  r.id = id;
  const bool ok = write(kIdName, false, &r, sizeof(r));
  crypto::wipe(&r, sizeof(r));
  if (ok) {
    memcpy(idPub_, id.pub, kKeyLen);
    hasId_ = true;
  }
  return ok;
}

// The epoch lives in the identity record.
bool SealedNvsStorage::nextEpoch(uint32_t &epoch) {
  IdRecord r;
  bool ok = ready_ && read(kIdName, false, &r, sizeof(r)) == Read::Ok;
  if (ok) {
    ++r.epoch;
    ok = write(kIdName, false, &r, sizeof(r));
  }
  if (ok) epoch = r.epoch;
  crypto::wipe(&r, sizeof(r));
  return ok;
}

bool SealedNvsStorage::loadPeer(size_t slot, PeerRecord &out) {
  if (slot >= slots_ || !ready_ || !hasId_) return false;
  char name[4];
  nvs::slotName('s', slot, name);
  return read(name, true, &out, sizeof(out)) == Read::Ok;
}

bool SealedNvsStorage::savePeer(size_t slot, const PeerRecord &rec) {
  if (slot >= slots_ || !ready_ || !hasId_) return false;
  char name[4];
  nvs::slotName('s', slot, name);
  return write(name, true, &rec, sizeof(rec));
}

bool SealedNvsStorage::erasePeer(size_t slot) {
  if (slot >= slots_ || !open_) return false;
  char name[4];
  nvs::slotName('s', slot, name);
  return !prefs_.isKey(name) || prefs_.remove(name);
}

bool SealedNvsStorage::eraseAll() {
  hasId_ = false;
  if (!openNamespace()) return false;
  bool ok = !prefs_.isKey(kIdName) || prefs_.remove(kIdName);
  for (size_t i = 0; i < nvs::kMaxSlots; ++i) {
    char name[4];
    nvs::slotName('s', i, name);
    if (prefs_.isKey(name) && !prefs_.remove(name)) ok = false;
  }
  return ok;
}

// Authenticated with each record but not stored: the namespace, the record
// name and, for a peer, the identity it belongs to.
size_t SealedNvsStorage::context(const char *name, bool bound, uint8_t *out) const {
  size_t n = addName(out, ns_);
  n += addName(out + n, name);
  if (bound) {
    memcpy(out + n, idPub_, kKeyLen);
    n += kKeyLen;
  }
  return n;
}

SealedNvsStorage::Read SealedNvsStorage::read(const char *name, bool bound, void *data,
                                              size_t len) {
  if (!prefs_.isKey(name)) return Read::Missing;
  uint8_t blob[kMaxRecord + seal::kOverhead];
  uint8_t ctx[seal::kMaxContext];
  const size_t n = len + seal::kOverhead;
  const size_t ctxLen = context(name, bound, ctx);
  const bool ok = len <= kMaxRecord && prefs_.getBytesLength(name) == n &&
                  prefs_.getBytes(name, blob, n) == n &&
                  seal::open(keys_, ctx, ctxLen, blob, n, data, len);
  if (!ok) crypto::wipe(data, len);
  return ok ? Read::Ok : Read::Damaged;
}

bool SealedNvsStorage::write(const char *name, bool bound, const void *data, size_t len) {
  uint8_t blob[kMaxRecord + seal::kOverhead];
  uint8_t ctx[seal::kMaxContext];
  const size_t n = len + seal::kOverhead;
  const size_t ctxLen = context(name, bound, ctx);
  return len <= kMaxRecord && seal::seal(keys_, ctx, ctxLen, data, len, blob) &&
         prefs_.putBytes(name, blob, n) == n;
}

}  // namespace securepair
