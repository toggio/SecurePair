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
 * One pairing attempt, start to end (docs/PROTOCOL.md).
 * Blocking; runs in the caller's context or in the short-lived pairing task.
 */

#pragma once

#include <atomic>

#include "../PairConfig.h"
#include "../PairTransport.h"
#include "../PairDisplay.h"
#include "PeerTable.h"
#include "Protocol.h"

namespace securepair {

class PairEngine {
 public:
  PairEngine(PairTransport &transport, CodeDisplay &codeDisplay, StatusDisplay &statusDisplay,
             PeerTable &table)
      : tr_(transport), ver_(codeDisplay), ui_(statusDisplay), table_(table) {}

  void setIdentity(const uint8_t priv[32], const uint8_t pub[32]);

  PairResult run(const PairConfig &config, PairInput *input, PairEventFn events, uint32_t epoch);

  void confirm() { confirmReq_ = true; }
  void reject() { rejectReq_ = true; }
  void cancel() { cancelReq_ = true; }
  void clearRequests();

 private:
  enum class Role : uint8_t { Unknown, Offerer, Responder };

  PairResult handshake(uint32_t &t0);
  PairResult onHandshakeMessage(const uint8_t *msg, size_t len, const SyncMark &mark, uint32_t &t0,
                                bool &anchored);
  PairResult confirmPhase(uint32_t baseUs);
  PairResult finish(PairResult r);

  bool sendReliable(const uint8_t *msg, size_t len, bool anchors);
  void sendAbort(uint8_t reason);
  /** The peer sends with the key we keep as the previous one: it has not seen our current one. */
  bool peerBehind(const uint8_t peerSends[kKeyIdLen]) const;
  /** The keyId we send to the peer with now; zeros if we have no record of it. */
  void sendsWith(uint8_t kid[kKeyIdLen]) const;
  size_t buildAuth(uint8_t *out, proto::MsgType type, const char *label,
                   const uint8_t *extra = nullptr, size_t extraLen = 0);
  bool checkAuth(const uint8_t *msg, size_t len, const char *label, size_t macLen);
  void pollInput();
  void emit(PairState state);
  uint32_t randomMs(uint32_t lo, uint32_t hi);
  bool expired(uint32_t deadlineMs) { return (int32_t)(tr_.millis() - deadlineMs) >= 0; }
  void wipeSession();

  PairTransport &tr_;
  CodeDisplay &ver_;
  StatusDisplay &ui_;
  PeerTable &table_;
  uint8_t idPriv_[32] = {}, idPub_[32] = {};

  std::atomic<bool> confirmReq_{false}, rejectReq_{false}, cancelReq_{false};
  const PairConfig *cfg_ = nullptr;
  PairInput *input_ = nullptr;
  PairEventFn events_ = nullptr;
  uint32_t epoch_ = 0;
  PairEvent ev_ = {};

  // One attempt.
  uint32_t startMs_ = 0;
  Role role_ = Role::Unknown;
  uint8_t ePriv_[32], ePub_[32], nonce_[proto::kNonceLen];
  uint8_t xidOwn_[kXidLen], commitOwn_[32];
  uint8_t xid_[kXidLen], commit_[32];
  bool haveXid_ = false, haveReveal_ = false, haveIdent_ = false;
  uint8_t peerIdPub_[32];
  proto::Stage1 s1_;
  proto::Stage2 s2_;
  PeerId peerId_ = {};

  // Last reliable message, resent when the peer shows it did not get it.
  uint8_t lastOut_[kMaxPairMessage];
  size_t lastOutLen_ = 0;
  bool lastOutAnchors_ = false;
  uint32_t resendAtMs_ = 0;
  bool needSync_ = false;
  uint8_t syncTries_ = 0;
  bool anchoredBySend_ = false;
  uint32_t sendMarkUs_ = 0;
};

}  // namespace securepair
