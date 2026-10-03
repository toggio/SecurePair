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
 * Timing helper shared by the UI adapters.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>

namespace securepair {

/** Sleeps until `at` (micros), then spins for the last 2 ms: the code's blinks stay in step. */
inline void waitUntilUs(uint32_t at) {
  while ((int32_t)(at - micros()) > 2000) delay(1);
  while ((int32_t)(at - micros()) > 0) {
  }
}

}  // namespace securepair

#endif
