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
 * Moving packets, whatever the medium: used for pairing, and by SecureLink for
 * messages. See EXTENDING.md for the contract and the ready-made adapters.
 */

#pragma once

#include "PairTypes.h"

namespace securepair {

/**
 * Instant an exchange completed, on both sides: the sender when the
 * acknowledgement has been read, the receiver when it has been sent.
 * Used as the common start (t0) of the code and of the confirmation cycles.
 */
struct SyncMark {
  uint32_t atUs;
  bool exact;          // false after retransmissions: the two sides may disagree
};

class PairTransport {
 public:
  virtual ~PairTransport() {}

  /** Largest payload send() accepts. Pairing messages need 58 bytes. */
  virtual size_t maxPayload() const = 0;

  /**
   * Blocking send.
   * @param reliable true: wait for the acknowledgement, with retries; return
   *                 whether it came. false: send once, without waiting.
   * @param mark     may be null; filled when the send returns.
   */
  virtual bool send(const uint8_t *data, size_t len, bool reliable, SyncMark *mark) = 0;

  /**
   * Waits up to `timeoutMs` for a packet.
   * @return its size, 0 on timeout. `mark` (may be null) is filled on success.
   */
  virtual int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) = 0;

  virtual uint32_t micros() = 0;
  virtual uint32_t millis() = 0;
  virtual void delayMs(uint32_t ms) = 0;

  /**
   * Optional: stop and restart the medium. SecurePair calls them around a
   * pairing on another medium, if asked to (SecurePair::pauseDuringPairing()).
   */
  virtual void pause() {}
  virtual void resume() {}

  /** Optional physical noise for the random pool (for example ADC readings). */
  virtual size_t entropy(uint8_t *buf, size_t cap) {
    (void)buf;
    (void)cap;
    return 0;
  }
};

}  // namespace securepair
