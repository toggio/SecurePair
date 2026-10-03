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
 * The code printed as a 6-digit number (and as its short/long pattern), on
 * Serial or any other Print: a display driver works too. Both boards need a
 * display the user can compare: two numbers, or two LEDs.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>

#include "../PairDisplay.h"
#include "UiTiming.h"

namespace securepair {

class SerialCodeDisplay : public CodeDisplay {
 public:
  explicit SerialCodeDisplay(Print &out) : out_(out) {}

  void show(const PairCode &code, uint32_t startUs, uint32_t durationMs) override {
    (void)durationMs;   // a number needs no time to be shown
    waitUntilUs(startUs);
    char digits[8];
    snprintf(digits, sizeof(digits), "%06u", (unsigned)code.digits());
    out_.printf("\n  Code: %.3s %.3s   (", digits, digits + 3);
    for (uint8_t i = 0; i < kCodeBits; ++i) out_.print(code.bitAt(i) ? '-' : '.');
    out_.println(")\n  Same code on the other board? Press to confirm, hold to reject.\n");
  }

 private:
  Print &out_;
};

}  // namespace securepair

#endif
