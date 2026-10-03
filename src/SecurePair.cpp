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
 * Lifecycle: identity, boot epoch, peers, repair window, task.
 */

#include "SecurePair.h"

#include "internal/Crypto.h"
#include "internal/Protocol.h"

#if defined(ESP_PLATFORM)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#else
#include <thread>
#endif

namespace securepair {

SecurePair::SecurePair(PairTransport &transport, PairStorage &storage, CodeDisplay &codeDisplay,
                       StatusDisplay &statusDisplay)
    : tr_(transport),
      st_(storage),
      ui_(statusDisplay),
      table_(storage),
      engine_(transport, codeDisplay, statusDisplay, table_) {}

bool SecurePair::begin(const PairConfig &config) {
  cfg_ = config;
  if (!st_.begin()) return false;

  uint8_t noise[64];
  const size_t got = tr_.entropy(noise, sizeof(noise));
  crypto::addEntropy(noise, got);

  if (st_.loadIdentity(id_)) {
    // A damaged private key would silently produce another identity: refuse it.
    static const uint8_t basePoint[32] = {9};
    uint8_t pub[32];
    if (!crypto::x25519(pub, id_.priv, basePoint) || !crypto::equal(pub, id_.pub, 32)) return false;
  } else {
    if (!crypto::x25519Keypair(id_.priv, id_.pub) || !st_.saveIdentity(id_)) return false;
  }
  proto::peerIdFromPub(id_.pub, localId_);
  engine_.setIdentity(id_.priv, id_.pub);

  // A new epoch on every boot keeps nonces unique without saving counters.
  if (!st_.nextEpoch(epoch_)) return false;
  if (!table_.load(cfg_.maxPeers)) return false;

  beginMs_ = tr_.millis();
  windowClosed_ = false;
  if (hasPeer()) ui_.play(StatusPattern::Ready);
  return true;
}

bool SecurePair::peerInfo(size_t index, PeerInfo &out) const {
  PeerRecord r;
  if (!table_.at(index, r)) return false;
  out.id = r.id;
  out.proven = !(r.flags & PeerRecord::kUnproven);
  out.keyChanging = (r.flags & PeerRecord::kHasAlt) != 0;
  out.pairedEpoch = r.pairedEpoch;
  crypto::wipe(&r, sizeof(r));
  return true;
}

bool SecurePair::repairWindowOpen() const {
  if (cfg_.policy == PairConfig::Policy::Always) return true;
  return !windowClosed_ && tr_.millis() - beginMs_ < cfg_.repairWindowMs;
}

PairResult SecurePair::attempt(PairInput *input) {
  for (PairTransport *t : paused_)
    if (t) t->pause();
  const PairResult r = engine_.run(cfg_, input, events_, epoch_);
  for (PairTransport *t : paused_)
    if (t) t->resume();
  last_ = r;
  // A failed re-pairing leaves the old association: say it is still there.
  if (r != PairResult::Ok && hasPeer()) ui_.play(StatusPattern::Ready);
  return r;
}

PairResult SecurePair::pair(PairInput *input) {
  if (epoch_ == 0) return PairResult::StorageError;   // begin() did not succeed
  if (busy_.exchange(true)) return PairResult::Busy;
  const PairResult r = attempt(input);
  busy_ = false;
  return r;
}

PairResult SecurePair::provision(PairInput &input) {
  if (epoch_ == 0) return PairResult::StorageError;   // begin() did not succeed
  // Held as the board started: the user asks for a pairing, peers or not.
  PairResult result = input.heldAtStart() ? pair(&input) : PairResult::Ok;
  while (!hasPeer()) {
    ui_.play(StatusPattern::Unpaired);
    const uint32_t t = tr_.millis();
    while (tr_.millis() - t < 3000) {
      if (input.read() == PairButton::Short) {
        result = pair(&input);
        break;
      }
      tr_.delayMs(20);
    }
  }
  return result;
}

bool SecurePair::handle(PairButton press) {
  if (busy_) {
    if (press == PairButton::Short) confirm();
    if (press == PairButton::Long) reject();
    return true;
  }
  return press == PairButton::Long && hasPeer() && repairWindowOpen() && requestPairing();
}

void SecurePair::pauseDuringPairing(PairTransport &transport) {
  for (PairTransport *&t : paused_) {
    if (t == &transport) return;
    if (!t) {
      t = &transport;
      return;
    }
  }
}

bool SecurePair::owns(const PairTransport &t) const {
  if (!busy_) return false;
  if (&t == &tr_) return true;
  for (const PairTransport *p : paused_)
    if (p == &t) return true;
  return false;
}

void SecurePair::taskEntry(void *self) {
  SecurePair *sp = static_cast<SecurePair *>(self);
  sp->attempt(nullptr);
  sp->busy_ = false;
#if defined(ESP_PLATFORM)
  vTaskDelete(nullptr);
#endif
}

bool SecurePair::requestPairing() {
  if (epoch_ == 0 || (hasPeer() && !repairWindowOpen())) return false;
  if (busy_.exchange(true)) return false;
#if defined(ESP_PLATFORM)
  // One priority above the caller (loop): PacketLED needs precise timing, and
  // it yields while listening, so loop() keeps running between frames.
  const UBaseType_t prio = uxTaskPriorityGet(nullptr) + 1;
  if (xTaskCreate(taskEntry, "SecurePair", 8192, this, prio, nullptr) != pdPASS) {
    busy_ = false;
    return false;
  }
#else
  std::thread(taskEntry, this).detach();
#endif
  return true;
}

const char *SecurePair::resultText(PairResult r) {
  switch (r) {
    case PairResult::Ok: return "ok";
    case PairResult::NoPeer: return "no peer";
    case PairResult::Timeout: return "timeout";
    case PairResult::Rejected: return "rejected";
    case PairResult::Cancelled: return "cancelled";
    case PairResult::ProtocolError: return "protocol error";
    case PairResult::StorageFull: return "storage full";
    case PairResult::StorageError: return "storage error";
    case PairResult::CryptoError: return "crypto error";
    case PairResult::Busy: return "busy";
  }
  return "?";
}

const char *SecurePair::stateText(PairState s) {
  switch (s) {
    case PairState::Armed: return "ARMED";
    case PairState::Starting: return "STARTING";
    case PairState::Rendezvous: return "RENDEZVOUS";
    case PairState::Exchange: return "EXCHANGE";
    case PairState::ShowCode: return "CODE";
    case PairState::WaitConfirm: return "WAIT_CONFIRM";
    case PairState::WaitPeerConfirm: return "WAIT_PEER_CONFIRM";
    case PairState::Commit: return "COMMIT";
    case PairState::Saved: return "SAVED";
    case PairState::Failed: return "FAILED";
  }
  return "?";
}

}  // namespace securepair
