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
 * Patterns and code on one LED.
 *
 * Grammar: short = information, long at the end = success, 10 Hz flicker = error
 * (and nothing else). The code runs on a fixed grid of 20 slots, a rhythm of its own.
 */

#ifdef ARDUINO

#include "LedDisplay.h"

#include "UiTiming.h"

namespace securepair {

void LedDisplay::blink(uint32_t onMs, uint32_t offMs) {
  led_.set(true);
  delay(onMs);
  led_.set(false);
  if (offMs) delay(offMs);
}

void LedDisplay::play(StatusPattern pattern) {
  LedArbiter *arb = led_.arbiter();
  if (arb && !arb->acquire(LedOwner::Status)) return;   // the transport has priority: skip
  switch (pattern) {
    case StatusPattern::Unpaired:
    case StatusPattern::WaitPeerConfirm:
      blink(t_.shortMs, 0);
      break;
    case StatusPattern::Ready:
      blink(t_.readyMs, 0);
      break;
    case StatusPattern::Armed:
      blink(t_.shortMs, t_.gapMs);
      blink(t_.shortMs, 0);
      break;
    case StatusPattern::Starting:
      // Countdown: three blinks one second apart, then dark while the LEDs are faced.
      for (int i = 0; i < 3; ++i) blink(t_.shortMs, i < 2 ? 1000 - t_.shortMs : 0);
      break;
    case StatusPattern::WaitConfirm:
      blink(t_.shortMs, 120);
      blink(t_.shortMs, 0);
      break;
    case StatusPattern::Saved:
      for (int i = 0; i < 3; ++i) blink(60, 60);
      blink(t_.longMs, 0);
      break;
    case StatusPattern::Error:
      for (int r = 0; r < 2; ++r) {
        for (int i = 0; i < 10; ++i) blink(t_.flickerMs, t_.flickerMs);
        if (r == 0) delay(500);
      }
      break;
  }
  led_.set(false);
  delay(t_.phyGuardMs);
  if (arb) arb->release(LedOwner::Status);
}

void LedDisplay::show(const PairCode &code, uint32_t startUs, uint32_t durationMs) {
  LedArbiter *arb = led_.arbiter();
  if (arb && !arb->acquire(LedOwner::Code)) return;
  const uint32_t slotUs = durationMs * 1000u / kCodeBits;
  for (uint8_t i = 0; i < kCodeBits; ++i) {
    const uint32_t slot = startUs + i * slotUs;
    waitUntilUs(slot);
    led_.set(true);
    waitUntilUs(slot + slotUs / 100 * (code.bitAt(i) ? t_.codeOnePct : t_.codeZeroPct));
    led_.set(false);
  }
  if (arb) arb->release(LedOwner::Code);
}

}  // namespace securepair

#endif
