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
 * Pairing state machine.
 *
 * Offerer and responder are only turn-taking roles: both run this code, and
 * the higher exchange ID (xid) wins the right to offer. Keys are symmetric.
 */

#include "PairEngine.h"

#include <string.h>

namespace securepair {

using namespace proto;

void PairEngine::setIdentity(const uint8_t priv[32], const uint8_t pub[32]) {
  memcpy(idPriv_, priv, 32);
  memcpy(idPub_, pub, 32);
}

void PairEngine::clearRequests() {
  confirmReq_ = false;
  rejectReq_ = false;
  cancelReq_ = false;
}

void PairEngine::pollInput() {
  if (!input_) return;
  const PairButton b = input_->read();
  if (b == PairButton::Short) confirmReq_ = true;
  if (b == PairButton::Long) rejectReq_ = true;
}

void PairEngine::emit(PairState state) {
  ev_.state = state;
  if (events_) events_(ev_);
}

uint32_t PairEngine::randomMs(uint32_t lo, uint32_t hi) {
  if (hi <= lo) return lo;
  uint32_t r;
  crypto::randomBytes(&r, sizeof(r));
  return lo + r % (hi - lo + 1);
}

void PairEngine::wipeSession() {
  crypto::wipe(ePriv_, sizeof(ePriv_));
  crypto::wipe(&s1_, sizeof(s1_));
  crypto::wipe(&s2_, sizeof(s2_));
  crypto::wipe(lastOut_, sizeof(lastOut_));
  lastOutLen_ = 0;
}

// --- Sending ----------------------------------------------------------------

bool PairEngine::sendReliable(const uint8_t *msg, size_t len, bool anchors) {
  memcpy(lastOut_, msg, len);
  lastOutLen_ = len;
  lastOutAnchors_ = anchors;
  SyncMark m = {};
  const bool ok = tr_.send(lastOut_, lastOutLen_, true, &m);
  resendAtMs_ = tr_.millis() + (ok ? cfg_->resendMs : randomMs(300, 800));
  if (anchors && ok) {
    if (m.exact) {
      anchoredBySend_ = true;
      sendMarkUs_ = m.atUs;
      needSync_ = false;
    } else {
      needSync_ = true;   // the peer anchored on an earlier copy: send SAS_SYNC
    }
  }
  return ok;
}

size_t PairEngine::buildAuth(uint8_t *out, MsgType type, const char *label, const uint8_t *extra,
                             size_t extraLen) {
  size_t n = header(out, type, xid_);
  if (extraLen) memcpy(out + n, extra, extraLen);
  n += extraLen;
  const size_t macLen = type == kSasSync ? kMac8 : kMac16;
  mac(s2_.cfSelf, label, out, s2_.th2, out + kHeaderLen, extraLen, out + n, macLen);
  return n + macLen;
}

bool PairEngine::checkAuth(const uint8_t *msg, size_t len, const char *label, size_t macLen) {
  if (!haveIdent_ || len < kHeaderLen + macLen) return false;
  const size_t extraLen = len - kHeaderLen - macLen;
  uint8_t calc[kMac16];
  mac(s2_.cfPeer, label, msg, s2_.th2, msg + kHeaderLen, extraLen, calc, macLen);
  return crypto::equal(calc, msg + len - macLen, macLen);
}

void PairEngine::sendAbort(uint8_t reason) {
  const uint8_t *xid = haveXid_ ? xid_ : nullptr;
  if (!xid) return;   // nobody to tell yet
  uint8_t m[kAbortAuthLen];
  size_t n = header(m, kAbort, xid);
  m[n++] = reason;
  if (haveIdent_) {
    mac(s2_.cfSelf, "abort", m, s2_.th2, &reason, 1, m + n, kMac16);
    n += kMac16;
  }
  tr_.send(m, n, true, nullptr);
}

// --- Attempt ----------------------------------------------------------------

PairResult PairEngine::run(const PairConfig &config, PairInput *input, PairEventFn events,
                           uint32_t epoch) {
  cfg_ = &config;
  input_ = input;
  events_ = events;
  epoch_ = epoch;
  wipeSession();
  role_ = Role::Unknown;
  haveXid_ = haveReveal_ = haveIdent_ = false;
  needSync_ = anchoredBySend_ = false;
  syncTries_ = 0;
  ev_ = PairEvent();
  clearRequests();
  startMs_ = tr_.millis();

  emit(PairState::Armed);
  ui_.play(StatusPattern::Armed);
  emit(PairState::Starting);
  ui_.play(StatusPattern::Starting);
  while (!expired(startMs_ + cfg_->alignPauseMs)) {
    pollInput();
    if (cancelReq_ || rejectReq_) return finish(PairResult::Cancelled);
    tr_.delayMs(10);
  }

  uint8_t noise[64];
  const size_t got = tr_.entropy(noise, sizeof(noise));
  crypto::addEntropy(noise, got);
  if (!crypto::x25519Keypair(ePriv_, ePub_)) return finish(PairResult::CryptoError);
  crypto::randomBytes(nonce_, sizeof(nonce_));
  crypto::randomBytes(xidOwn_, sizeof(xidOwn_));
  commitment(xidOwn_, ePub_, nonce_, commitOwn_);

  emit(PairState::Rendezvous);
  uint32_t t0 = 0;
  const PairResult r = handshake(t0);
  if (r != PairResult::Ok) return finish(r);

  emit(PairState::ShowCode);
  const uint32_t sasStart = t0 + cfg_->codeLeadMs * 1000u;
  const uint32_t sasEnd = sasStart + cfg_->codeMs * 1000u;
  ver_.show(ev_.code, sasStart, cfg_->codeMs);
  // A press during the code does not confirm: whoever pressed had not seen it
  // all. A long one rejects, as soon as the code ends.
  while ((int32_t)(sasEnd - tr_.micros()) > 1000) {
    pollInput();
    tr_.delayMs(1);
  }
  pollInput();
  if (input_) input_->clear();
  confirmReq_ = false;
  return finish(confirmPhase(sasEnd));
}

PairResult PairEngine::finish(PairResult r) {
  ev_.result = r;
  if (r == PairResult::Ok) {
    emit(PairState::Saved);
    ui_.play(StatusPattern::Saved);
  } else {
    emit(PairState::Failed);
    ui_.play(StatusPattern::Error);
  }
  wipeSession();
  return r;
}

// --- OFFER / REVEAL / IDENT / SAS_SYNC ----------------------------------------

PairResult PairEngine::handshake(uint32_t &t0) {
  const uint32_t rendezvousEnd = startMs_ + cfg_->rendezvousMs;
  const uint32_t exchangeEnd = startMs_ + cfg_->exchangeMs;
  uint32_t nextOfferMs = tr_.millis() + randomMs(0, cfg_->offerMaxMs);
  bool anchored = false;
  uint8_t buf[64];

  for (;;) {
    if (anchoredBySend_) {
      anchoredBySend_ = false;
      t0 = sendMarkUs_;
      anchored = true;
      lastOutLen_ = 0;   // nothing more to send before the SAS
    }
    pollInput();
    if (cancelReq_ || rejectReq_) {
      sendAbort(kAbortUser);
      return PairResult::Cancelled;
    }
    const bool offering = role_ != Role::Responder && !haveReveal_;
    if (expired(offering ? rendezvousEnd : exchangeEnd)) {
      sendAbort(kAbortTimeout);
      return offering ? PairResult::NoPeer : PairResult::Timeout;
    }
    if (anchored) {
      // Listen until shortly before the SAS: a later SAS_SYNC or ABORT may come.
      const int32_t left = (int32_t)(t0 + cfg_->codeLeadMs * 1000u - tr_.micros());
      if (left <= 2 * (int32_t)cfg_->pollMs * 1000) return PairResult::Ok;
    }

    if (offering && expired(nextOfferMs)) {
      uint8_t m[kOfferLen];
      const size_t n = header(m, kOffer, xidOwn_);
      memcpy(m + n, commitOwn_, 32);
      tr_.send(m, sizeof(m), false, nullptr);
      nextOfferMs = tr_.millis() + randomMs(cfg_->offerMinMs, cfg_->offerMaxMs);
    } else if (needSync_) {
      if (++syncTries_ > 4) return PairResult::Timeout;
      uint8_t m[kSasSyncLen];
      const size_t n = buildAuth(m, kSasSync, "sync");
      SyncMark mk = {};
      if (tr_.send(m, n, true, &mk) && mk.exact) {
        needSync_ = false;
        t0 = mk.atUs;
        anchored = true;
      }
    } else if (lastOutLen_ && expired(resendAtMs_)) {
      sendReliable(lastOut_, lastOutLen_, lastOutAnchors_);
    }

    SyncMark mark = {};
    const int n = tr_.receive(buf, sizeof(buf), cfg_->pollMs, &mark);
    if (n > 0) {
      const PairResult r = onHandshakeMessage(buf, (size_t)n, mark, t0, anchored);
      if (r != PairResult::Ok) return r;
    }
  }
}

PairResult PairEngine::onHandshakeMessage(const uint8_t *msg, size_t len, const SyncMark &mark,
                                          uint32_t &t0, bool &anchored) {
  MsgType type;
  if (!parseHeader(msg, len, type)) return PairResult::Ok;
  const uint8_t *mx = msg + 2;
  const uint8_t *body = msg + kHeaderLen;
  const bool ourXid = haveXid_ && memcmp(mx, xid_, kXidLen) == 0;

  switch (type) {
    case kOffer:
      if (role_ == Role::Responder) {
        // The offerer is still offering: it did not get our REVEAL.
        if (ourXid && !haveReveal_ && lastOutLen_) sendReliable(lastOut_, lastOutLen_, false);
      } else if (!haveReveal_ && memcmp(mx, xidOwn_, kXidLen) > 0) {
        // Higher xid: that board offers, this one responds.
        role_ = Role::Responder;
        memcpy(xid_, mx, kXidLen);
        memcpy(commit_, body, 32);
        haveXid_ = true;
        emit(PairState::Exchange);
        uint8_t m[kRevealLen];
        size_t k = header(m, kReveal, xid_);
        memcpy(m + k, ePub_, 32);
        memcpy(m + k + 32, nonce_, kNonceLen);
        sendReliable(m, sizeof(m), false);
      }
      break;

    case kReveal:
      if (role_ != Role::Responder && !haveReveal_) {
        if (memcmp(mx, xidOwn_, kXidLen) != 0) break;
        role_ = Role::Offerer;
        memcpy(xid_, xidOwn_, kXidLen);
        memcpy(commit_, commitOwn_, 32);
        haveXid_ = true;
        if (!deriveStage1(xid_, commit_, ePriv_, ePub_, nonce_, body, body + 32, s1_))
          return PairResult::ProtocolError;
        haveReveal_ = true;
        ev_.code = s1_.sas;
        emit(PairState::Exchange);
        uint8_t m[kRevealLen];
        size_t k = header(m, kReveal, xid_);
        memcpy(m + k, ePub_, 32);
        memcpy(m + k + 32, nonce_, kNonceLen);
        sendReliable(m, sizeof(m), false);
      } else if (role_ == Role::Offerer && ourXid && !haveIdent_ && lastOutLen_) {
        sendReliable(lastOut_, lastOutLen_, false);   // our REVEAL did not arrive
      } else if (role_ == Role::Responder && ourXid) {
        if (!haveReveal_) {
          uint8_t c[32];
          commitment(xid_, body, body + 32, c);
          if (!crypto::equal(c, commit_, 32)) return PairResult::ProtocolError;
          if (!deriveStage1(xid_, commit_, ePriv_, ePub_, nonce_, body, body + 32, s1_))
            return PairResult::ProtocolError;
          haveReveal_ = true;
          ev_.code = s1_.sas;
          uint8_t m[kIdentLen];
          const size_t k = header(m, kIdent, xid_);
          sealIdent(s1_.hsSelf, m, idPub_, m + k);
          sendReliable(m, sizeof(m), false);
        } else if (!haveIdent_ && lastOutLen_) {
          sendReliable(lastOut_, lastOutLen_, false);   // our IDENT did not arrive
        }
      }
      break;

    case kIdent:
      if (!haveReveal_ || !ourXid) break;
      if (!haveIdent_) {
        if (!openIdent(s1_.hsPeer, msg, body, peerIdPub_)) return PairResult::ProtocolError;
        if (!deriveStage2(s1_, idPriv_, idPub_, peerIdPub_, s2_)) return PairResult::ProtocolError;
        peerIdFromPub(peerIdPub_, peerId_);
        haveIdent_ = true;
        ev_.peer = peerId_;
        ev_.repair = table_.contains(peerId_);
        if (!table_.canStore(peerId_)) {
          sendAbort(kAbortStorageFull);
          return PairResult::StorageFull;
        }
        if (role_ == Role::Offerer) {
          uint8_t m[kIdentLen];
          const size_t k = header(m, kIdent, xid_);
          sealIdent(s1_.hsSelf, m, idPub_, m + k);
          sendReliable(m, sizeof(m), true);   // its end is t0
        } else {
          t0 = mark.atUs;
          anchored = true;
          lastOutLen_ = 0;
        }
      } else if (role_ == Role::Responder) {
        // A later copy: the offerer anchors on its last successful send.
        t0 = mark.atUs;
        anchored = true;
      }
      break;

    case kSasSync:
      if (role_ == Role::Responder && ourXid && checkAuth(msg, len, "sync", kMac8)) {
        t0 = mark.atUs;
        anchored = true;
      }
      break;

    case kAbort: {
      const bool match = ourXid || (!haveXid_ && memcmp(mx, xidOwn_, kXidLen) == 0);
      if (!match) break;
      if (haveIdent_ && !(len == kAbortAuthLen && checkAuth(msg, len, "abort", kMac16))) break;
      return body[0] == kAbortStorageFull ? PairResult::StorageFull : PairResult::Rejected;
    }

    default:
      break;
  }
  return PairResult::Ok;
}

// --- CONFIRM / DONE -----------------------------------------------------------

void PairEngine::sendsWith(uint8_t kid[kKeyIdLen]) const {
  PeerRecord r;
  if (table_.find(peerId_, r)) {
    memcpy(kid, r.keyId, kKeyIdLen);
  } else {
    memset(kid, 0, kKeyIdLen);
  }
  crypto::wipe(&r, sizeof(r));
}

bool PairEngine::peerBehind(const uint8_t peerSends[kKeyIdLen]) const {
  PeerRecord r;
  const bool behind = table_.find(peerId_, r) && (r.flags & PeerRecord::kHasAlt) &&
                      !(r.flags & PeerRecord::kAltIsNew) &&
                      memcmp(r.altKeyId, peerSends, kKeyIdLen) == 0;
  crypto::wipe(&r, sizeof(r));
  return behind;
}

PairResult PairEngine::confirmPhase(uint32_t baseUs) {
  emit(PairState::WaitConfirm);

  // The key each board sends to the other with, told in CONFIRM and DONE:
  // with it, a re-pairing still pending from before is settled before the new
  // key is saved, a peer that lost its records is recognized (zeros), and the
  // old key is dropped only once the peer sends with the new one.
  uint8_t peerSends[kKeyIdLen] = {};
  static const uint8_t kNone[kKeyIdLen] = {};
  bool peerUsesNew = false;          // the peer's DONE names the new key
  uint8_t doneKid[kKeyIdLen] = {};   // the key named in our last DONE

  const uint32_t deadline = tr_.millis() + cfg_->confirmMs;
  bool mine = false, peerConfirmed = false, peerSaved = false;
  bool saved = false, savedKnowingPeer = false;
  bool confirmDelivered = false, doneDelivered = false, resendDone = false;
  uint32_t savedAtMs = 0;
  PeerTable::Undo undo;
  uint8_t buf[64];
  const uint32_t cycleUs = cfg_->cycleMs * 1000u;

  for (uint32_t k = 0;; ++k) {
    const uint32_t cycleStart = baseUs + k * cycleUs;
    if ((int32_t)(tr_.micros() - (cycleStart + cycleUs)) >= 0) continue;   // already past
    while ((int32_t)(cycleStart - tr_.micros()) > 0) tr_.delayMs(1);
    // UI slot, at the same time on both boards: nobody is listening now.
    if ((int32_t)(tr_.micros() - cycleStart) < 50000)
      ui_.play(mine || saved ? StatusPattern::WaitPeerConfirm : StatusPattern::WaitConfirm);

    const uint32_t sendAt = cycleStart + (cfg_->uiSlotMs + randomMs(0, cfg_->sendJitterMs)) * 1000u;
    const uint32_t windowEnd = cycleStart + cycleUs - cfg_->pollMs * 1000u;
    bool sent = false;

    while ((int32_t)(tr_.micros() - windowEnd) < 0) {
      pollInput();
      // Once saved, the peer may have saved too: an ABORT now could leave the two
      // boards with different keys. From here on only the peer's messages count.
      if (!saved && (cancelReq_ || rejectReq_)) {
        const bool cancelled = cancelReq_;
        sendAbort(kAbortUser);
        return cancelled ? PairResult::Cancelled : PairResult::Rejected;
      }
      rejectReq_ = false;
      cancelReq_ = false;
      if (confirmReq_ && !mine) {
        mine = true;
        emit(PairState::WaitPeerConfirm);
      }
      confirmReq_ = false;

      // The peer still sends with our previous key: saving would drop it. Only
      // the peer's DONE proves it has saved, and moved to our current key (it
      // learns it from our CONFIRM). A transport acknowledgement does not: it
      // may come from another board, or from a peer that then fails to save.
      if (mine && peerConfirmed && !saved && (peerSaved || !peerBehind(peerSends))) {
        // Write-ahead: saved before telling the peer (DONE).
        emit(PairState::Commit);
        const bool peerHasKey = memcmp(peerSends, kNone, kKeyIdLen) != 0;
        if (!table_.saveCandidate(peerId_, peerIdPub_, s2_.linkKey, s2_.keyId, peerSaved,
                                  peerHasKey ? peerSends : nullptr, epoch_, undo)) {
          sendAbort(kAbortProtocol);
          return PairResult::StorageError;
        }
        saved = true;
        savedKnowingPeer = peerSaved;
        savedAtMs = tr_.millis();
      }
      // The old key goes only when the peer's own DONE says it sends with the
      // new one. Our DONE acknowledged proves nothing of the kind: the
      // acknowledgement may come from another board, and the peer may fail to
      // save the change.
      if (saved && peerUsesNew && doneDelivered && !resendDone) {
        table_.finalize(peerId_, s2_.keyId);
        return PairResult::Ok;
      }
      if (saved && expired(savedAtMs + cfg_->commitMs)) {
        // Otherwise the old key goes with the peer's first frame under the new one.
        if (peerUsesNew) table_.finalize(peerId_, s2_.keyId);
        return PairResult::Ok;
      }
      if (!saved && expired(deadline)) {
        sendAbort(kAbortTimeout);
        return PairResult::Timeout;
      }

      if (!sent && (int32_t)(tr_.micros() - sendAt) >= 0) {
        uint8_t m[kDoneLen], kid[kKeyIdLen];
        sendsWith(kid);
        if (saved && (!doneDelivered || resendDone)) {
          const size_t n = buildAuth(m, kDone, "done", kid, kKeyIdLen);
          memcpy(doneKid, kid, kKeyIdLen);
          if (tr_.send(m, n, true, nullptr)) {
            doneDelivered = true;
            resendDone = false;
          }
          sent = true;
        } else if (!saved && mine && !confirmDelivered) {
          const size_t n = buildAuth(m, kConfirm, "confirm", kid, kKeyIdLen);
          confirmDelivered = tr_.send(m, n, true, nullptr);
          sent = true;
        }
      }

      const int n = tr_.receive(buf, sizeof(buf), cfg_->pollMs, nullptr);
      if (n <= 0) continue;
      MsgType type;
      if (!parseHeader(buf, (size_t)n, type) || memcmp(buf + 2, xid_, kXidLen) != 0) continue;
      if (type == kConfirm && checkAuth(buf, n, "confirm", kMac16)) {
        memcpy(peerSends, buf + kHeaderLen, kKeyIdLen);
        peerConfirmed = true;
        if (saved) resendDone = true;
      } else if (type == kDone && checkAuth(buf, n, "done", kMac16)) {
        memcpy(peerSends, buf + kHeaderLen, kKeyIdLen);
        peerConfirmed = peerSaved = true;
        if (memcmp(peerSends, s2_.keyId, kKeyIdLen) == 0) peerUsesNew = true;
        if (saved && !savedKnowingPeer) {
          table_.promote(peerId_, s2_.keyId);
          savedKnowingPeer = true;
          // Now sending with another key (unless the write failed): tell the
          // peer, which waits for that before dropping the old one.
          uint8_t kid[kKeyIdLen];
          sendsWith(kid);
          if (memcmp(kid, doneKid, kKeyIdLen) != 0) resendDone = true;
        }
      } else if (type == kAbort && n == (int)kAbortAuthLen && checkAuth(buf, n, "abort", kMac16)) {
        // The peer aborts only before saving: undo a save it cannot match.
        if (!saved) return PairResult::Rejected;
        if (!savedKnowingPeer) {
          table_.rollback(undo);
          return PairResult::Rejected;
        }
      }
    }
  }
}

}  // namespace securepair
