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
 * Status patterns and code on one plain LED: the PacketLED one (pass the
 * PacketLedTransport) or any other (GpioLedSink).
 */

#pragma once

#ifdef ARDUINO

#include "../PairDisplay.h"

namespace securepair {

/** Timings in milliseconds (docs/ARCHITECTURE.md, "LED patterns"). */
struct LedTiming {
  uint16_t shortMs = 80;
  uint16_t gapMs = 150;
  uint16_t readyMs = 250;
  uint16_t longMs = 1000;
  uint16_t flickerMs = 50;        // 10 Hz: error only
  uint8_t codeZeroPct = 24;       // code bit 0: LED on for this share of the slot (120 of 500 ms)
  uint8_t codeOnePct = 70;        // code bit 1 (350 of 500 ms)
  uint16_t phyGuardMs = 100;      // LED off before handing it back to PacketLED
};

class LedDisplay : public CodeDisplay, public StatusDisplay {
 public:
  explicit LedDisplay(LedSink &led, const LedTiming &timing = LedTiming()) : led_(led), t_(timing) {}

  void show(const PairCode &code, uint32_t startUs, uint32_t durationMs) override;
  void play(StatusPattern pattern) override;

 private:
  void blink(uint32_t onMs, uint32_t offMs);

  LedSink &led_;
  LedTiming t_;
};

}  // namespace securepair

#endif
