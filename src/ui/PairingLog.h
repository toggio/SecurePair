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
 * What SecurePair is doing, in plain words, on any Print (usually Serial).
 * The examples use it:
 *
 *   void onPairEvent(const PairEvent &e) { logPairingEvent(Serial, e); }
 *
 *   pairing.onEvent(onPairEvent);
 *   pairing.begin();
 *   logPairingStatus(Serial, pairing, storage.encrypted());
 */

#pragma once

#include <Print.h>

#include "../SecurePair.h"

namespace securepair {

/** The 8 bytes of a board's identity, as 16 hex digits. */
inline void logPeerId(Print &out, const PeerId &id) {
  for (uint8_t b : id.b) out.printf("%02X", b);
}

/** This board, how its keys are kept, and the boards it is paired with. Call after begin(). */
inline void logPairingStatus(Print &out, SecurePair &pairing, bool keysEncrypted) {
  if (pairing.epoch() == 0) {   // begin() did not succeed
    out.println(keysEncrypted ? "Saved keys do not open (damaged, or written by another chip): no pairing"
                              : "Storage not available: no pairing");
    return;
  }
  out.print("This board is ");
  logPeerId(out, pairing.localId());
  out.println(keysEncrypted ? ", keys encrypted with the chip key"
                            : ", keys in clear (see the ChipKeySetup example)");
  PeerInfo peer;
  for (size_t i = 0; pairing.peerInfo(i, peer); ++i) {
    out.print("Paired with ");
    logPeerId(out, peer.id);
    out.println();
  }
  if (!pairing.hasPeer()) out.println("Not paired yet: start a pairing on both boards");
}

/** One line per step of a pairing. */
inline void logPairingEvent(Print &out, const PairEvent &e) {
  switch (e.state) {
    case PairState::Starting: out.println("Pairing: started"); break;
    case PairState::Rendezvous: out.println("Pairing: looking for the other board"); break;
    case PairState::Exchange: out.println("Pairing: exchanging keys"); break;
    case PairState::ShowCode:
      out.printf("Pairing: code %06u, compare it with the other board\n", (unsigned)e.code.digits());
      break;
    case PairState::WaitConfirm: out.println("Pairing: same code? Confirm, or reject"); break;
    case PairState::WaitPeerConfirm: out.println("Pairing: confirmed, waiting for the other board"); break;
    case PairState::Saved:
      out.println(e.repair ? "Pairing: done, new key for a board already paired"
                           : "Pairing: done, new board");
      break;
    case PairState::Failed: out.printf("Pairing: failed (%s)\n", SecurePair::resultText(e.result)); break;
    default: break;
  }
}

}  // namespace securepair
