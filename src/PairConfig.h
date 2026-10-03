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
 * Configuration and public peer information.
 */

#pragma once

#include "PairTypes.h"

namespace securepair {

struct PairConfig {
  enum class Policy : uint8_t {
    BootWindow,      // pairing again only within repairWindowMs of begin()
    Always,          // whenever the application asks (handle(), requestPairing())
  };

  Policy policy = Policy::BootWindow;
  uint32_t repairWindowMs = 10000;
  uint32_t alignPauseMs = 3000;         // after the press: time to face the LEDs
  uint32_t rendezvousMs = 20000;        // from the press: nobody answered -> NoPeer
  uint32_t exchangeMs = 40000;          // from the press, until the code
  uint32_t confirmMs = 30000;           // from the end of the code
  uint8_t maxPeers = 8;                 // capped by PairStorage::capacity()

  // Protocol timing: the same on both boards. The defaults suit PacketLED at 1024 bit/s.
  uint16_t offerMinMs = 300;            // pause between two OFFERs, random in [min, max]
  uint16_t offerMaxMs = 1500;
  uint16_t resendMs = 2500;             // resend the last message if the peer is silent
  uint16_t codeLeadMs = 3000;           // end of the exchange -> start of the code
  uint16_t codeMs = 10000;              // how long the code is shown, whatever the display
  uint16_t cycleMs = 2000;              // waiting for confirmation: one cycle...
  uint16_t uiSlotMs = 400;              // ... starts with the status blink, then messages
  uint16_t sendJitterMs = 600;          // random delay of a send in the message part
  uint16_t commitMs = 6000;             // after saving, how long to wait for the peer's DONE
  uint16_t pollMs = 30;                 // receive granularity

  /** Shorter pauses for a fast medium with no LEDs to face: ESP-NOW, LoRa at low spreading factors. */
  static PairConfig forRadio() {
    PairConfig c;
    c.alignPauseMs = 500;
    c.offerMinMs = 100;
    c.offerMaxMs = 400;
    c.resendMs = 500;
    c.codeLeadMs = 1000;
    return c;
  }
};

/** Public view of a peer (no keys). */
struct PeerInfo {
  PeerId id;
  bool proven;         // false: first pairing saved, the peer's DONE not seen yet
  bool keyChanging;    // true: two keys held while a re-pairing converges
  uint32_t pairedEpoch;
};

}  // namespace securepair
