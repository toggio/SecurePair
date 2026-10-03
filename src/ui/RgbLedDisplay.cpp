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
 * Patterns and code on a WS2812 RGB LED.
 * Same grammar as LedDisplay (short = information, long = success, flicker =
 * error), plus color: blue information, amber question, green good, red bad.
 */

#ifdef ARDUINO

#include "RgbLedDisplay.h"

#include "UiTiming.h"

namespace securepair {

void RgbLedDisplay::set(Rgb c) {
  rgbLedWriteOrdered(pin_, order_, c.r * brightness_ / 255, c.g * brightness_ / 255,
                     c.b * brightness_ / 255);
}

void RgbLedDisplay::blink(Rgb c, uint32_t onMs, uint32_t offMs) {
  set(c);
  delay(onMs);
  off();
  if (offMs) delay(offMs);
}

void RgbLedDisplay::play(StatusPattern pattern) {
  switch (pattern) {
    case StatusPattern::Unpaired:
      blink(info, 80, 0);
      break;
    case StatusPattern::Ready:
      blink(good, 250, 0);
      break;
    case StatusPattern::Armed:
      blink(info, 80, 150);
      blink(info, 80, 0);
      break;
    case StatusPattern::Starting:
      for (int i = 0; i < 3; ++i) blink(info, 80, i < 2 ? 920 : 0);
      break;
    case StatusPattern::WaitConfirm:
      blink(ask, 80, 120);
      blink(ask, 80, 0);
      break;
    case StatusPattern::WaitPeerConfirm:
      blink(ask, 80, 0);
      break;
    case StatusPattern::Saved:
      for (int i = 0; i < 3; ++i) blink(good, 60, 60);
      blink(good, 1000, 0);
      break;
    case StatusPattern::Error:
      for (int r = 0; r < 2; ++r) {
        for (int i = 0; i < 10; ++i) blink(bad, 50, 50);
        if (r == 0) delay(500);
      }
      break;
  }
  off();
}

// Blink i: its length is bit i, its color bits i+1 and i+2 (wrapping around).
void RgbLedDisplay::show(const PairCode &code, uint32_t startUs, uint32_t durationMs) {
  const uint32_t slotUs = durationMs * 1000u / kCodeBits;
  for (uint8_t i = 0; i < kCodeBits; ++i) {
    const uint32_t slot = startUs + i * slotUs;
    const bool one = code.bitAt(i);
    const uint8_t color = code.bitAt((i + 1) % kCodeBits) << 1 | code.bitAt((i + 2) % kCodeBits);
    waitUntilUs(slot);
    set(codeColors[color]);
    waitUntilUs(slot + slotUs / 100 * (one ? 70 : 24));
    off();
  }
}

}  // namespace securepair

#endif
