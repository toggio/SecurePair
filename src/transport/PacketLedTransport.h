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
 * PairTransport and LedSink over an existing PacketLED object.
 *
 * PacketLED is used through its public API only. The sync mark is the SyncBlink
 * technique: the sender takes it when endPacket() returns, the receiver when
 * parsePacket() returns, after sending its acknowledgement.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>
#include <PacketLED.h>

#include "../LedArbiter.h"
#include "../PairTransport.h"
#include "../PairDisplay.h"

namespace securepair {

class PacketLedTransport : public PairTransport, public LedSink {
 public:
  explicit PacketLedTransport(PacketLED &led) : led_(led) {}

  size_t maxPayload() const override { return lx25::kMaxPayload; }

  bool send(const uint8_t *data, size_t len, bool reliable, SyncMark *mark) override {
    if (!arbiter_.acquire(LedOwner::Transport)) return false;
    led_.beginPacket();
    led_.write(data, len);
    const bool ok = led_.endPacket(reliable);
    if (mark) {
      mark->atUs = ::micros();
      mark->exact = ok && reliable && led_.lastAttempts() == 1;
    }
    arbiter_.release(LedOwner::Transport);
    return ok;
  }

  int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) override {
    if (!arbiter_.acquire(LedOwner::Transport)) return 0;
    const uint32_t start = ::millis();
    int n = 0;
    do {
      const int size = led_.parsePacket();
      if (size > 0) {
        if (mark) {
          mark->atUs = ::micros();
          // Only the sender knows whether it retransmitted (duplicates are
          // acknowledged but not returned). If it did, it follows up with
          // SAS_SYNC and the engine moves t0.
          mark->exact = true;
        }
        for (int i = 0; i < size; ++i) {
          const int b = led_.read();
          if (i < (int)cap) buf[n++] = (uint8_t)b;
        }
        break;
      }
    } while (::millis() - start < timeoutMs);
    arbiter_.release(LedOwner::Transport);
    return n;
  }

  uint32_t micros() override { return ::micros(); }
  uint32_t millis() override { return ::millis(); }
  void delayMs(uint32_t ms) override { ::delay(ms); }

  /** Low bits of short dark readings: sensor and ADC noise for the random pool. */
  size_t entropy(uint8_t *buf, size_t cap) override {
    if (!arbiter_.acquire(LedOwner::Transport)) return 0;
    size_t n = 0;
    while (n + 4 <= cap) {
      const uint16_t v = led_.measureLight(100);
      const uint16_t t = (uint16_t)::micros();
      buf[n++] = (uint8_t)v;
      buf[n++] = (uint8_t)(v >> 8);
      buf[n++] = (uint8_t)t;
      buf[n++] = (uint8_t)(t >> 8);
    }
    arbiter_.release(LedOwner::Transport);
    return n;
  }

  // LedSink: status patterns and code on the same LED.
  void set(bool on) override { led_.setLed(on); }
  LedArbiter *arbiter() override { return &arbiter_; }

 private:
  PacketLED &led_;
  LedArbiter arbiter_;
};

}  // namespace securepair

#endif
