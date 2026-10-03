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
 * Encrypted, authenticated messages between paired boards.
 *
 * Frame (29 bytes of overhead):
 *
 *   | type 1 | keyId 4 | epoch 4 | counter 4 | ciphertext n | tag 16 |
 *
 * AES-256-GCM with one key per direction, derived from the pairing key.
 * Nonce = epoch || counter: the epoch is the sender's boot counter (saved in
 * NVS by SecurePair::begin()), the counter restarts at every boot.
 *
 * The receiver accepts each (epoch, counter) once. After its own reboot it no
 * longer remembers the counters of a peer that did not reboot: the first
 * message from that peer is then refused and answered with a challenge; the
 * peer's proof restores the counter, and from there messages flow again.
 * sync() does this in advance for every peer.
 *
 * SecureLink may use the pairing transport or another one: for example pair
 * over the LEDs, then talk over ESP-NOW. The keys do not depend on the medium.
 * Several SecureLinks of the same pairing (one per medium) share counters and
 * replay windows, so they can be used side by side.
 */

#pragma once

#include "SecurePair.h"

namespace securepair {

class SecureLink {
 public:
  static constexpr uint8_t kTypeData = 0x21;
  static constexpr uint8_t kTypeChallenge = 0x22;
  static constexpr uint8_t kTypeProof = 0x23;
  static constexpr size_t kHeaderLen = 13;
  static constexpr size_t kTagLen = 16;
  static constexpr size_t kOverhead = kHeaderLen + kTagLen;
  static constexpr size_t kMaxFrame = 256;

  enum class SendResult : uint8_t {
    Ok,
    NotDelivered,   // reliable send not acknowledged (may still have arrived)
    UnknownPeer,
    BadLength,      // empty, or longer than maxPayload()
    Busy,           // a pairing is using this transport
    NotReady,       // SecurePair::begin() failed or was not called
    Exhausted,      // 2^32 frames to this peer in one boot: restart the board
    CryptoError,    // the encryption failed: nothing was sent
  };

  struct Stats {
    uint32_t sent, received;
    uint32_t foreign;      // not a SecureLink frame (e.g. pairing traffic)
    uint32_t unknownKey;   // no peer with that key
    uint32_t replayed;     // epoch or counter already seen
    uint32_t badAuth;      // tag mismatch: tampered, reflected or wrong key
    uint32_t tooLong;      // did not fit the caller's buffer
    uint32_t refused;      // not provably fresh after our reboot: challenge sent
    uint32_t proofs;       // challenges answered for the peers
    uint32_t keyUpdates;   // re-pairings completed by traffic
    uint32_t notSaved;     // not delivered: the peer's new epoch could not be saved
  };

  /** Uses the pairing transport. */
  explicit SecureLink(SecurePair &pairing) : SecureLink(pairing, pairing.tr_) {}
  /** Uses another transport, e.g. EspNowTransport after pairing over the LEDs. */
  SecureLink(SecurePair &pairing, PairTransport &transport) : sp_(pairing), tr_(transport) {}

  /** Largest message: transport payload minus 29 bytes (35 with PacketLED, 217 with ESP-NOW). */
  size_t maxPayload() const;

  SendResult send(const PeerId &to, const uint8_t *data, size_t len, bool reliable = true);
  SendResult send(const PeerId &to, const char *text);

  /**
   * Waits up to `timeoutMs` for a message (0: check once). Call it regularly:
   * it also answers the challenges of rebooted peers.
   * @return its size, 0 if none. `from` tells who sent it.
   */
  int receive(uint8_t *buf, size_t cap, PeerId &from, uint32_t timeoutMs = 0);

  /**
   * Challenges every peer, so that after a reboot their first message is not
   * refused. The answers are handled by receive(). Returns the number of
   * challenges delivered.
   */
  size_t sync();
  /** true once `peer` has proven its counter (or rebooted) since our boot. */
  bool synced(const PeerId &peer);

  /**
   * false: accept the first message after our reboot without a challenge.
   * Only for one-way links, where the peer cannot answer. After our reboot,
   * each message the peer sent since its own last reboot can then be
   * replayed once.
   */
  void requireFreshness(bool on) { requireFresh_ = on; }

  const Stats &stats() const { return stats_; }
  static const char *resultText(SendResult r);

 private:
  enum class Fresh : uint8_t { Old, New, Unknown };
  using PeerState = SecurePair::LinkPeer;   // kept in SecurePair, shared by all links

  PeerState *state(const PeerId &id);
  Fresh classify(const PeerState &s, uint32_t floorEpoch, uint32_t epoch, uint32_t counter) const;
  static void mark(PeerState &s, uint32_t epoch, uint32_t counter);
  SendResult seal(uint8_t type, const PeerId &to, const uint8_t *data, size_t len, bool reliable);
  bool challenge(PeerState &s);
  bool usable() const;

  SecurePair &sp_;
  PairTransport &tr_;
  bool requireFresh_ = true;
  Stats stats_ = {};
};

}  // namespace securepair
