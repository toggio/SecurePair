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
 * Peer records.
 */

#include "PeerTable.h"

#include <string.h>

#include "Crypto.h"

namespace securepair {

namespace {
constexpr uint8_t kRecordFormat = 1;

// The alternate key becomes the current one, and the other way round.
void swapKeys(PeerRecord &r) {
  uint8_t k[32], kid[kKeyIdLen];
  memcpy(k, r.key, 32);
  memcpy(kid, r.keyId, kKeyIdLen);
  memcpy(r.key, r.altKey, 32);
  memcpy(r.keyId, r.altKeyId, kKeyIdLen);
  memcpy(r.altKey, k, 32);
  memcpy(r.altKeyId, kid, kKeyIdLen);
  crypto::wipe(k, sizeof(k));
}

bool holds(const PeerRecord &r, const uint8_t keyId[kKeyIdLen]) {
  return memcmp(r.keyId, keyId, kKeyIdLen) == 0 ||
         ((r.flags & PeerRecord::kHasAlt) && memcmp(r.altKeyId, keyId, kKeyIdLen) == 0);
}
}  // namespace

bool PeerTable::load(size_t maxPeers) {
  std::lock_guard<std::mutex> lock(m_);
  slots_ = maxPeers;
  if (slots_ > st_.capacity()) slots_ = st_.capacity();
  if (slots_ > kMaxSlots) slots_ = kMaxSlots;
  for (size_t i = 0; i < kMaxSlots; ++i) {
    used_[i] = i < slots_ && st_.loadPeer(i, rec_[i]) && rec_[i].format == kRecordFormat;
    if (!used_[i]) crypto::wipe(&rec_[i], sizeof(PeerRecord));
  }
  return true;
}

size_t PeerTable::count() const {
  std::lock_guard<std::mutex> lock(m_);
  size_t n = 0;
  for (size_t i = 0; i < slots_; ++i) n += used_[i];
  return n;
}

bool PeerTable::at(size_t index, PeerRecord &out) const {
  std::lock_guard<std::mutex> lock(m_);
  for (size_t i = 0; i < slots_; ++i) {
    if (!used_[i]) continue;
    if (index-- == 0) {
      out = rec_[i];
      return true;
    }
  }
  return false;
}

int PeerTable::slotOf(const PeerId &id) const {
  for (size_t i = 0; i < slots_; ++i)
    if (used_[i] && rec_[i].id == id) return (int)i;
  return -1;
}

bool PeerTable::find(const PeerId &id, PeerRecord &out) const {
  std::lock_guard<std::mutex> lock(m_);
  const int s = slotOf(id);
  if (s < 0) return false;
  out = rec_[s];
  return true;
}

bool PeerTable::contains(const PeerId &id) const {
  std::lock_guard<std::mutex> lock(m_);
  return slotOf(id) >= 0;
}

bool PeerTable::canStore(const PeerId &id) const {
  std::lock_guard<std::mutex> lock(m_);
  if (slotOf(id) >= 0) return true;
  for (size_t i = 0; i < slots_; ++i)
    if (!used_[i]) return true;
  return false;
}

bool PeerTable::write(int slot, const PeerRecord &rec) {
  if (!st_.savePeer(slot, rec)) return false;
  rec_[slot] = rec;
  used_[slot] = true;
  return true;
}

bool PeerTable::saveCandidate(const PeerId &id, const uint8_t idPub[32], const uint8_t key[32],
                              const uint8_t keyId[kKeyIdLen], bool peerSaved,
                              const uint8_t *peerSends, uint32_t epoch, Undo &undo) {
  std::lock_guard<std::mutex> lock(m_);
  int slot = slotOf(id);
  undo = Undo();
  if (slot >= 0) {
    undo.hadRecord = true;
    undo.prev = rec_[slot];
  } else {
    for (size_t i = 0; i < slots_ && slot < 0; ++i)
      if (!used_[i]) slot = (int)i;
    if (slot < 0) return false;
  }
  undo.slot = slot;

  PeerRecord old = undo.prev;
  bool keepOld = undo.hadRecord;
  if (keepOld) {
    // The peer sends with the key still pending here, so it has saved it:
    // settle that as a message under it would (promote()), then rotate.
    // Otherwise two re-pairings cut short in a row could leave each board
    // without the key the other sends with.
    if (peerSends && (old.flags & PeerRecord::kAltIsNew) &&
        memcmp(old.altKeyId, peerSends, kKeyIdLen) == 0) {
      swapKeys(old);
      old.flags = PeerRecord::kHasAlt;
    }
    // The peer uses none of our keys (it lost its records): they are worth
    // nothing, and neither is the epoch saved for them. Start over.
    keepOld = peerSends && holds(old, peerSends);
  }

  PeerRecord r = {};
  r.format = kRecordFormat;
  r.id = id;
  memcpy(r.idPub, idPub, 32);
  r.pairedEpoch = epoch;
  if (!keepOld) {
    // First pairing with this peer, or starting over: nothing older to fall back to.
    memcpy(r.key, key, 32);
    memcpy(r.keyId, keyId, kKeyIdLen);
    r.flags = peerSaved ? 0 : PeerRecord::kUnproven;
  } else {
    r.rxEpoch = old.rxEpoch;
    if (peerSaved) {
      memcpy(r.key, key, 32);
      memcpy(r.keyId, keyId, kKeyIdLen);
      memcpy(r.altKey, old.key, 32);
      memcpy(r.altKeyId, old.keyId, kKeyIdLen);
      r.flags = PeerRecord::kHasAlt;
    } else {
      memcpy(r.key, old.key, 32);
      memcpy(r.keyId, old.keyId, kKeyIdLen);
      memcpy(r.altKey, key, 32);
      memcpy(r.altKeyId, keyId, kKeyIdLen);
      r.flags = PeerRecord::kHasAlt | PeerRecord::kAltIsNew;
    }
  }
  const bool ok = write(slot, r);
  crypto::wipe(&r, sizeof(r));
  crypto::wipe(&old, sizeof(old));
  return ok;
}

bool PeerTable::promote(const PeerId &id, const uint8_t keyId[kKeyIdLen]) {
  std::lock_guard<std::mutex> lock(m_);
  const int s = slotOf(id);
  if (s < 0) return false;
  PeerRecord r = rec_[s];
  if ((r.flags & PeerRecord::kAltIsNew) && memcmp(r.altKeyId, keyId, kKeyIdLen) == 0) {
    swapKeys(r);
    r.flags = PeerRecord::kHasAlt;
  } else if ((r.flags & PeerRecord::kUnproven) && memcmp(r.keyId, keyId, kKeyIdLen) == 0) {
    r.flags &= ~PeerRecord::kUnproven;
  } else {
    return true;  // nothing to do
  }
  const bool ok = write(s, r);
  crypto::wipe(&r, sizeof(r));
  return ok;
}

bool PeerTable::finalize(const PeerId &id, const uint8_t keyId[kKeyIdLen]) {
  std::lock_guard<std::mutex> lock(m_);
  const int s = slotOf(id);
  if (s < 0) return false;
  PeerRecord r = rec_[s];
  if (memcmp(r.keyId, keyId, kKeyIdLen) != 0) return false;
  if (r.flags == 0) return true;
  crypto::wipe(r.altKey, sizeof(r.altKey));
  crypto::wipe(r.altKeyId, sizeof(r.altKeyId));
  r.flags = 0;
  const bool ok = write(s, r);
  crypto::wipe(&r, sizeof(r));
  return ok;
}

bool PeerTable::rollback(const Undo &undo) {
  std::lock_guard<std::mutex> lock(m_);
  if (undo.slot < 0) return false;
  if (undo.hadRecord) {
    // Epochs accepted since the save stay refused.
    PeerRecord r = undo.prev;
    const PeerRecord &now = rec_[undo.slot];
    if (used_[undo.slot] && now.id == r.id && now.rxEpoch > r.rxEpoch) r.rxEpoch = now.rxEpoch;
    const bool ok = write(undo.slot, r);
    crypto::wipe(&r, sizeof(r));
    return ok;
  }
  if (!st_.erasePeer(undo.slot)) return false;
  used_[undo.slot] = false;
  crypto::wipe(&rec_[undo.slot], sizeof(PeerRecord));
  return true;
}

size_t PeerTable::withKeyId(const uint8_t keyId[kKeyIdLen], PeerRecord *out, size_t max) const {
  std::lock_guard<std::mutex> lock(m_);
  size_t n = 0;
  for (size_t i = 0; i < slots_ && n < max; ++i) {
    if (!used_[i]) continue;
    const PeerRecord &r = rec_[i];
    if (memcmp(r.keyId, keyId, kKeyIdLen) == 0 ||
        ((r.flags & PeerRecord::kHasAlt) && memcmp(r.altKeyId, keyId, kKeyIdLen) == 0))
      out[n++] = r;
  }
  return n;
}

bool PeerTable::raiseRxEpoch(const PeerId &id, uint32_t epoch) {
  std::lock_guard<std::mutex> lock(m_);
  const int s = slotOf(id);
  if (s < 0) return false;
  if (epoch <= rec_[s].rxEpoch) return true;
  PeerRecord r = rec_[s];
  r.rxEpoch = epoch;
  const bool ok = write(s, r);
  crypto::wipe(&r, sizeof(r));
  return ok;
}

bool PeerTable::forget(const PeerId &id) {
  std::lock_guard<std::mutex> lock(m_);
  const int s = slotOf(id);
  if (s < 0) return false;
  if (!st_.erasePeer(s)) return false;
  used_[s] = false;
  crypto::wipe(&rec_[s], sizeof(PeerRecord));
  return true;
}

bool PeerTable::forgetAll() {
  std::lock_guard<std::mutex> lock(m_);
  bool ok = true;
  for (size_t i = 0; i < slots_; ++i) {
    if (!used_[i]) continue;
    if (st_.erasePeer(i)) {
      used_[i] = false;
      crypto::wipe(&rec_[i], sizeof(PeerRecord));
    } else {
      ok = false;
    }
  }
  return ok;
}

}  // namespace securepair
