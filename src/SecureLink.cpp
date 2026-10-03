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
 * Encrypted channel.
 */

#include "SecureLink.h"

#include <string.h>

#include "internal/Crypto.h"
#include "internal/Protocol.h"

namespace securepair {

namespace {

constexpr uint32_t kRechallengeMs = 1000;
constexpr size_t kChallengeLen = 8;

void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

// Nonce = epoch || counter || 0, taken from the frame header.
void makeNonce(uint8_t nonce[crypto::kGcmIvLen], const uint8_t *epochCounter) {
  memcpy(nonce, epochCounter, 8);
  memset(nonce + 8, 0, 4);
}

}  // namespace

size_t SecureLink::maxPayload() const {
  size_t p = tr_.maxPayload();
  if (p > kMaxFrame) p = kMaxFrame;
  return p > kOverhead ? p - kOverhead : 0;
}

bool SecureLink::usable() const {
  // A pairing owns its transport, and the ones paused for it; any other stays usable.
  return sp_.epoch_ != 0 && !sp_.owns(tr_);
}

SecureLink::PeerState *SecureLink::state(const PeerId &id) {
  PeerState *free = nullptr;
  for (PeerState &s : sp_.links_) {
    if (s.used && s.id == id) return &s;
    if (!s.used && !free) free = &s;
  }
  // All taken: reuse the entry of a peer that has been forgotten meanwhile.
  for (PeerState &s : sp_.links_)
    if (!free && !sp_.table_.contains(s.id)) free = &s;
  if (free) {
    *free = PeerState();
    free->id = id;
    free->used = true;
  }
  return free;
}

// Epochs below the saved one are old. A higher epoch means the peer rebooted
// after anything we accepted before: new. Within the current epoch a 64-frame
// window tolerates reordering. The saved epoch itself, before any frame of this
// boot, cannot be judged: we do not remember its counters (docs/PROTOCOL.md).
SecureLink::Fresh SecureLink::classify(const PeerState &s, uint32_t floorEpoch, uint32_t epoch,
                                       uint32_t counter) const {
  if (epoch < floorEpoch) return Fresh::Old;
  if (!s.seen) {
    if (epoch > floorEpoch || !requireFresh_) return Fresh::New;
    return Fresh::Unknown;
  }
  if (epoch > s.epoch) return Fresh::New;
  if (epoch < s.epoch) return Fresh::Old;
  if (counter > s.max) return Fresh::New;
  const uint32_t d = s.max - counter;
  return d < 64 && !((s.window >> d) & 1) ? Fresh::New : Fresh::Old;
}

void SecureLink::mark(PeerState &s, uint32_t epoch, uint32_t counter) {
  if (!s.seen || epoch > s.epoch) {
    s.epoch = epoch;
    s.max = counter;
    s.window = 1;
    s.seen = true;
  } else if (counter > s.max) {
    const uint32_t shift = counter - s.max;
    s.window = shift >= 64 ? 1 : (s.window << shift) | 1;
    s.max = counter;
  } else {
    s.window |= (uint64_t)1 << (s.max - counter);
  }
}

SecureLink::SendResult SecureLink::send(const PeerId &to, const char *text) {
  return send(to, reinterpret_cast<const uint8_t *>(text), strlen(text));
}

SecureLink::SendResult SecureLink::send(const PeerId &to, const uint8_t *data, size_t len,
                                        bool reliable) {
  if (len == 0 || len > maxPayload()) return SendResult::BadLength;
  return seal(kTypeData, to, data, len, reliable);
}

SecureLink::SendResult SecureLink::seal(uint8_t type, const PeerId &to, const uint8_t *data,
                                        size_t len, bool reliable) {
  if (sp_.epoch_ == 0) return SendResult::NotReady;
  if (!usable()) return SendResult::Busy;
  std::lock_guard<std::recursive_mutex> lock(sp_.linkMutex_);
  PeerRecord r;
  if (!sp_.table_.find(to, r)) return SendResult::UnknownPeer;
  PeerState *t = state(to);
  if (!t) return SendResult::UnknownPeer;
  if (t->txCounter == UINT32_MAX) return SendResult::Exhausted;

  uint8_t frame[kMaxFrame];
  frame[0] = type;
  memcpy(frame + 1, r.keyId, kKeyIdLen);   // the current key: the old one until a re-pairing is proven
  put32(frame + 5, sp_.epoch_);
  put32(frame + 9, t->txCounter++);        // consumed even if the send fails: never reused

  uint8_t key[32], nonce[crypto::kGcmIvLen];
  proto::directionalKey(r.key, sp_.localId_, to, key);
  makeNonce(nonce, frame + 5);
  const bool sealed = crypto::gcmEncrypt(key, nonce, frame, kHeaderLen, data, len,
                                         frame + kHeaderLen, frame + kHeaderLen + len);
  crypto::wipe(key, sizeof(key));
  crypto::wipe(&r, sizeof(r));
  if (!sealed) {
    crypto::wipe(frame, sizeof(frame));   // never send what may still be plaintext
    return SendResult::CryptoError;
  }

  const bool ok = tr_.send(frame, kOverhead + len, reliable, nullptr);
  if (ok && type == kTypeData) ++stats_.sent;
  return ok ? SendResult::Ok : SendResult::NotDelivered;
}

bool SecureLink::challenge(PeerState &s) {
  crypto::randomBytes(s.challenge, kChallengeLen);
  s.challenged = true;
  s.challengedAtMs = tr_.millis();
  return seal(kTypeChallenge, s.id, s.challenge, kChallengeLen, true) == SendResult::Ok;
}

size_t SecureLink::sync() {
  if (!usable()) return 0;
  std::lock_guard<std::recursive_mutex> lock(sp_.linkMutex_);
  size_t delivered = 0;
  PeerInfo p;
  for (size_t i = 0; sp_.peerInfo(i, p); ++i) {
    PeerState *s = state(p.id);
    if (s && !s->seen && challenge(*s)) ++delivered;
  }
  return delivered;
}

bool SecureLink::synced(const PeerId &peer) {
  std::lock_guard<std::recursive_mutex> lock(sp_.linkMutex_);
  PeerState *s = state(peer);
  return s && s->seen;
}

int SecureLink::receive(uint8_t *buf, size_t cap, PeerId &from, uint32_t timeoutMs) {
  if (!usable()) return 0;
  std::lock_guard<std::recursive_mutex> lock(sp_.linkMutex_);
  uint8_t frame[kMaxFrame];
  const int n = tr_.receive(frame, sizeof(frame), timeoutMs, nullptr);
  if (n <= 0) return 0;
  const uint8_t type = frame[0];
  if ((size_t)n < kOverhead || (type != kTypeData && type != kTypeChallenge && type != kTypeProof)) {
    ++stats_.foreign;
    return 0;
  }
  const size_t len = (size_t)n - kOverhead;
  const uint32_t epoch = get32(frame + 5);
  const uint32_t counter = get32(frame + 9);

  PeerRecord cand[4];
  const size_t found = sp_.table_.withKeyId(frame + 1, cand, 4);
  if (found == 0) {
    ++stats_.unknownKey;
    return 0;
  }

  int result = 0;
  bool authentic = false, old = false;
  for (size_t i = 0; i < found && !authentic; ++i) {
    PeerRecord &r = cand[i];
    PeerState *s = state(r.id);
    if (!s) continue;
    // The saved epoch went down: the peer was paired again from scratch, after
    // losing its records. Its old epochs no longer apply; start as after a reboot.
    if (s->seen && s->epoch > r.rxEpoch) {
      s->seen = false;
      s->challenged = false;
    }
    const Fresh fresh = classify(*s, r.rxEpoch, epoch, counter);
    if (fresh == Fresh::Old) {
      old = true;
      continue;
    }

    const bool isCurrent = memcmp(r.keyId, frame + 1, kKeyIdLen) == 0;
    uint8_t key[32], nonce[crypto::kGcmIvLen], plain[kMaxFrame];
    proto::directionalKey(isCurrent ? r.key : r.altKey, r.id, sp_.localId_, key);
    makeNonce(nonce, frame + 5);
    authentic = crypto::gcmDecrypt(key, nonce, frame, kHeaderLen, frame + kHeaderLen, len, plain,
                                   frame + kHeaderLen + len);
    crypto::wipe(key, sizeof(key));
    if (!authentic) continue;

    // Sent by the peer with this key, so the peer has saved it: finish a re-pairing.
    // A frame under the old key while the new one is pending proves nothing (it
    // may have been sent before the pairing), so it changes nothing.
    if (!isCurrent && (r.flags & PeerRecord::kAltIsNew)) {
      sp_.table_.promote(r.id, r.altKeyId);
      sp_.table_.finalize(r.id, r.altKeyId);
      ++stats_.keyUpdates;
    } else if (isCurrent && r.flags != 0 && !(r.flags & PeerRecord::kAltIsNew)) {
      sp_.table_.finalize(r.id, r.keyId);
      ++stats_.keyUpdates;
    }

    if (type == kTypeChallenge) {
      // Answering is harmless even for a replayed challenge: the proof is bound to its nonce.
      if (len == kChallengeLen && seal(kTypeProof, r.id, plain, len, true) == SendResult::Ok)
        ++stats_.proofs;
      if (fresh == Fresh::New) mark(*s, epoch, counter);
    } else if (type == kTypeProof) {
      // Our own fresh nonce inside: this frame is new, and so is its counter.
      if (s->challenged && len == kChallengeLen && crypto::equal(plain, s->challenge, len)) {
        s->challenged = false;
        if (!s->seen || epoch > s->epoch) {
          s->seen = false;
          mark(*s, epoch, counter);
          s->window = ~(uint64_t)0;   // everything sent before the proof counts as seen
        } else {
          // Frames of this epoch were accepted while the proof was on its way
          // (a delayed proof): the window only moves forward.
          mark(*s, epoch, counter);
        }
      }
    } else if (fresh == Fresh::Unknown) {
      ++stats_.refused;
      if (!s->challenged || tr_.millis() - s->challengedAtMs > kRechallengeMs) challenge(*s);
    } else if (epoch > r.rxEpoch && !sp_.table_.raiseRxEpoch(r.id, epoch)) {
      // A new epoch of the peer is saved before its first message is delivered:
      // after our own reboot, that message must stay refused. Not saved, not
      // delivered.
      ++stats_.notSaved;
    } else {
      mark(*s, epoch, counter);
      from = r.id;
      if (len > cap) {
        ++stats_.tooLong;
      } else {
        memcpy(buf, plain, len);
        ++stats_.received;
        result = (int)len;
      }
    }
    // Challenges and proofs: saved as well, once per peer reboot.
    if (type != kTypeData && s->seen && epoch > r.rxEpoch) sp_.table_.raiseRxEpoch(r.id, epoch);
    crypto::wipe(plain, sizeof(plain));
  }
  if (!authentic) {
    if (old) {
      ++stats_.replayed;
    } else {
      ++stats_.badAuth;
    }
  }
  for (PeerRecord &r : cand) crypto::wipe(&r, sizeof(r));
  return result;
}

const char *SecureLink::resultText(SendResult r) {
  switch (r) {
    case SendResult::Ok: return "ok";
    case SendResult::NotDelivered: return "not delivered";
    case SendResult::UnknownPeer: return "unknown peer";
    case SendResult::BadLength: return "bad length";
    case SendResult::Busy: return "busy (pairing)";
    case SendResult::NotReady: return "not ready";
    case SendResult::Exhausted: return "counter exhausted";
    case SendResult::CryptoError: return "encryption failed";
  }
  return "?";
}

}  // namespace securepair
