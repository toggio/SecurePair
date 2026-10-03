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
 * Pairing confirmed by a person, between any number of boards.
 *
 * Each board has a persistent identity. A pairing adds a new peer or, if the
 * peer is already known, replaces its key, only after both users have confirmed.
 *
 * An application needs one call: provision(), in setup(). It pairs on the
 * first start, and again when the button is held as the board starts; loop()
 * needs nothing. To pair while the application runs instead, pass the presses
 * to handle() in loop(). A pairing runs as one blocking attempt, either in
 * provision() or in a task that exists only for that attempt; outside of it
 * SecurePair does nothing. SecurePair never reads a pin itself: presses come
 * from a PairInput (such as ButtonInput) or from the application.
 */

#pragma once

#include <atomic>
#include <mutex>

#include "PairConfig.h"
#include "PairStorage.h"
#include "PairTransport.h"
#include "PairTypes.h"
#include "PairDisplay.h"
#include "internal/PairEngine.h"
#include "internal/PeerTable.h"

#define SECUREPAIR_VERSION "0.5.0"

namespace securepair {

class SecureLink;

class SecurePair {
 public:
  SecurePair(PairTransport &transport, PairStorage &storage, CodeDisplay &codeDisplay,
             StatusDisplay &statusDisplay);

  /**
   * Loads or creates the identity, advances the boot epoch, loads the peers.
   * With peers it plays READY and opens the repair window. Starts no task.
   * Call it after the transport has been started.
   */
  bool begin(const PairConfig &config = PairConfig());

  // --- Peers --------------------------------------------------------------
  bool hasPeer() const { return table_.count() > 0; }
  size_t peerCount() const { return table_.count(); }
  bool peerInfo(size_t index, PeerInfo &out) const;
  const PeerId &localId() const { return localId_; }
  uint32_t epoch() const { return epoch_; }
  bool forget(const PeerId &id) { return table_.forget(id); }
  bool forgetAll() { return table_.forgetAll(); }

  // --- Pairing ---------------------------------------------------------------
  /**
   * The one call an application needs, in setup(). If `input` was held as the
   * board started (PairInput::heldAtStart()), pairs at once: a new peer, or a
   * new key for a known one. Then, as long as there is no peer, blinks
   * UNPAIRED, waits for a Short press and pairs, until a peer is saved.
   * Returns Ok at once when there is nothing to do, otherwise the result of
   * the last attempt; StorageError if begin() did not succeed.
   */
  PairResult provision(PairInput &input);

  /**
   * Only to pair while the application runs: pass the user's presses from
   * loop().
   *   - during a pairing: Short confirms, Long rejects; returns true, and the
   *     pairing transport must not be used meanwhile;
   *   - within the repair window: Long starts a pairing; returns true;
   *   - otherwise: does nothing and returns false.
   * After the window it costs a couple of comparisons.
   */
  bool handle(PairButton press);

  /**
   * Stops `transport` (pause()) while a pairing runs, and restarts it after
   * (resume()). For a radio carrying messages while the LEDs pair, when
   * pairing while the application runs: Wi-Fi interrupts would disturb
   * PacketLED's timing. With provision() in setup(), start the radio after
   * it instead. Up to two transports.
   */
  void pauseDuringPairing(PairTransport &transport);

  // --- Lower level ----------------------------------------------------------
  /**
   * Runs one complete attempt, blocking: ARMED, STARTING, exchange, code,
   * confirmation. `input` is read for confirm (Short) and reject (Long); it
   * may be null if the application calls confirm() / reject() from elsewhere.
   */
  PairResult pair(PairInput *input = nullptr);

  /**
   * Runs pair() in a background task and returns at once. New peer or
   * re-pairing is decided by the peer's identity.
   * @return false if a pairing is running, or if there are peers and the
   *         repair window is closed.
   */
  bool requestPairing();

  /** User events; thread-safe, callable from loop(), another task or an ISR. */
  void confirm() { engine_.confirm(); }
  void reject() { engine_.reject(); }
  void cancel() { engine_.cancel(); }

  /** true while a pairing owns the transport and the LED. */
  bool busy() const { return busy_; }
  /** A comparison with millis(): no task and no polling behind it. */
  bool repairWindowOpen() const;
  void closeRepairWindow() { windowClosed_ = true; }
  PairResult lastResult() const { return last_; }

  /** Called on every state change, from the pairing task when there is one. Keep it short. */
  void onEvent(PairEventFn fn) { events_ = fn; }

  static const char *resultText(PairResult r);
  static const char *stateText(PairState s);

 private:
  friend class SecureLink;

  PairResult attempt(PairInput *input);
  /** true while a pairing uses or has paused `t`. */
  bool owns(const PairTransport &t) const;
  static void taskEntry(void *self);

  PairTransport &tr_;
  PairStorage &st_;
  StatusDisplay &ui_;
  PeerTable table_;
  PairEngine engine_;
  PairConfig cfg_;
  IdentityRecord id_ = {};
  PeerId localId_ = {};
  uint32_t epoch_ = 0;
  uint32_t beginMs_ = 0;
  bool windowClosed_ = false;
  std::atomic<bool> busy_{false};
  PairResult last_ = PairResult::Ok;
  PairEventFn events_ = nullptr;
  PairTransport *paused_[2] = {};

  // Message counters and replay windows, shared by every SecureLink of this
  // pairing: two links (say one over the LEDs, one over ESP-NOW) must never
  // reuse a nonce, nor both accept the same frame.
  struct LinkPeer {
    PeerId id;
    bool used;
    uint32_t txCounter;      // next counter to send with
    uint32_t epoch, max;     // highest (epoch, counter) received
    uint64_t window;         // bit i: counter max - i already received
    bool seen;               // a frame of this peer was accepted since our boot
    bool challenged;         // challenge outstanding
    uint32_t challengedAtMs;
    uint8_t challenge[8];
  };
  LinkPeer links_[PeerTable::kMaxSlots] = {};
  std::recursive_mutex linkMutex_;
};

}  // namespace securepair
