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
 * Who owns the (single) LED right now: the transport (PacketLED), a status
 * pattern or the code.
 * Inside the pairing engine ownership follows the state; the arbiter makes a
 * violation visible instead of silently corrupting a frame.
 */

#pragma once

#include <atomic>

#include "PairTypes.h"

namespace securepair {

enum class LedOwner : uint8_t { None, Transport, Status, Code };

class LedArbiter {
 public:
  LedOwner owner() const { return owner_.load(); }

  /** Takes the LED if it is free (or already ours). Never waits. */
  bool acquire(LedOwner who) {
    LedOwner expected = LedOwner::None;
    return owner_.compare_exchange_strong(expected, who) || expected == who;
  }

  void release(LedOwner who) {
    LedOwner expected = who;
    owner_.compare_exchange_strong(expected, LedOwner::None);
  }

 private:
  std::atomic<LedOwner> owner_{LedOwner::None};
};

}  // namespace securepair
