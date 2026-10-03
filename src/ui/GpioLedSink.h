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
 * A plain LED on a GPIO, for LedDisplay when the status LED is not
 * the PacketLED one.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>

#include "../PairDisplay.h"

namespace securepair {

class GpioLedSink : public LedSink {
 public:
  explicit GpioLedSink(uint8_t pin, bool activeLow = false) : pin_(pin), activeLow_(activeLow) {}

  /** Call once from setup(). */
  void begin() {
    pinMode(pin_, OUTPUT);
    set(false);
  }

  void set(bool on) override { digitalWrite(pin_, on != activeLow_ ? HIGH : LOW); }

 private:
  uint8_t pin_;
  bool activeLow_;
};

}  // namespace securepair

#endif
