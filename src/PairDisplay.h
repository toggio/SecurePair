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
 * The human side of pairing: the code (CodeDisplay), the status patterns
 * (StatusDisplay) and plain LEDs (LedSink). Ready-made implementations are in
 * ui/; EXTENDING.md explains how to write your own.
 */

#pragma once

#include "LedArbiter.h"
#include "PairTypes.h"

namespace securepair {

/** Anything that can turn one LED on and off. */
class LedSink {
 public:
  virtual ~LedSink() {}
  virtual void set(bool on) = 0;
  /** Arbiter shared with the transport when the LED is also the PacketLED one, else null. */
  virtual LedArbiter *arbiter() { return nullptr; }
};

/** Shows the code to the user. */
class CodeDisplay {
 public:
  virtual ~CodeDisplay() {}
  /**
   * Shows `code` starting exactly at `startUs` (micros), the same instant on
   * both boards, within `durationMs`. May return early (a printed number) or
   * at the end (a blinking LED); the pairing waits for the full duration anyway.
   */
  virtual void show(const PairCode &code, uint32_t startUs, uint32_t durationMs) = 0;
};

/**
 * Plays status patterns. play() runs one short burst and returns; the pairing
 * decides when and how often, so cyclic patterns stay aligned on both boards.
 */
class StatusDisplay {
 public:
  virtual ~StatusDisplay() {}
  virtual void play(StatusPattern pattern) = 0;
};

/** For boards without any status output. */
class NullStatusDisplay : public StatusDisplay {
 public:
  void play(StatusPattern) override {}
};

}  // namespace securepair
