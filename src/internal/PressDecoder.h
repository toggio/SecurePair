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
 * Short and long presses from the edges of a button (ButtonInput). Each press
 * is timed from its own edges, so one that ended before anybody asked still
 * has its real length: a hold that meant "reject" never turns into a Short
 * because read() came late. No I/O here: testable on the PC.
 */

#pragma once

#include <stdint.h>

#include "../PairTypes.h"

namespace securepair {

class PressDecoder {
 public:
  static constexpr uint32_t kBounceMs = 20;   // edges closer than this are contact bounce
  static constexpr uint32_t kSettleMs = 30;   // a level that disagrees this long settles a lost edge

  explicit PressDecoder(uint16_t longMs) : longMs_(longMs) {}

  /** The level when reading starts: a button already held gives no press at all. */
  void start(bool down, uint32_t now) {
    down_ = down;
    downAt_ = lastEdge_ = now;
    longSent_ = noShort_ = down;
    disagree_ = false;
    pending_ = PairButton::None;
  }

  /** An edge, from the interrupt: `down` is the level after it. */
  void edge(bool down, uint32_t now) {
    if (now - lastEdge_ < kBounceMs) return;
    lastEdge_ = now;
    change(down, now);
  }

  /**
   * Short once a press ends, Long as soon as it has lasted longMs (while still
   * held, or at its end if nobody asked before). A Long wins over a Short not
   * read yet, even while it is still held: that Short waits for the press to
   * end, so a rejection right after a confirmation is never too late.
   */
  PairButton read(bool down, uint32_t now) {
    // An edge lost in the bounce: a level that disagrees for a while settles
    // it. The lost edge came within kBounceMs of the last one seen.
    if (down == down_) {
      disagree_ = false;
    } else if (!disagree_) {
      disagree_ = true;
      disagreeAt_ = now;
    } else if (now - disagreeAt_ > kSettleMs) {
      disagree_ = false;
      change(down, lastEdge_);
    }
    if (down_ && !longSent_ && now - downAt_ >= longMs_) {
      longSent_ = true;
      pending_ = PairButton::None;   // a Short before it gives way
      return PairButton::Long;
    }
    if (pending_ == PairButton::Short && down_ && !longSent_) return PairButton::None;
    const PairButton p = pending_;
    pending_ = PairButton::None;
    return p;
  }

  /** Forgets presses not read yet; one still going on may end as Long, never as Short. */
  void clear() {
    pending_ = PairButton::None;
    noShort_ = true;   // a new press sets it back
  }

 private:
  void change(bool down, uint32_t at) {
    if (down == down_) return;
    down_ = down;
    if (down) {
      downAt_ = at;
      longSent_ = noShort_ = false;
      return;
    }
    if (longSent_) return;   // already told while it was held
    PairButton p = PairButton::None;
    if (at - downAt_ >= longMs_) {
      p = PairButton::Long;
    } else if (!noShort_) {
      p = PairButton::Short;
    }
    if (p != PairButton::None && pending_ != PairButton::Long) pending_ = p;
  }

  uint16_t longMs_;
  bool down_ = false;
  uint32_t downAt_ = 0, lastEdge_ = 0, disagreeAt_ = 0;
  bool longSent_ = false, noShort_ = false, disagree_ = false;
  PairButton pending_ = PairButton::None;
};

}  // namespace securepair
