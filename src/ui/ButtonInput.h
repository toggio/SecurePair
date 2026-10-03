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
 * A push button as PairInput: short and long presses, timed in an interrupt
 * so that no press is lost, and none changes kind, while a pairing keeps the
 * CPU busy. Held as the board starts, it asks provision() for a pairing
 * (heldAtStart()).
 * Optional: SecurePair works with any PairInput, or with confirm()/reject().
 *
 * Not on a boot strapping pin, such as the BOOT button (GPIO9 on the C3 and
 * C6, GPIO0 on the ESP32): held during a reset, it starts the ROM download
 * mode instead of the sketch.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>

#include "../PairTypes.h"
#include "../internal/PressDecoder.h"

namespace securepair {

class ButtonInput : public PairInput {
 public:
  /**
   * @param activeLow true: button to GND, internal pull-up (the usual wiring)
   * @param longMs    held this long, it is a Long press
   */
  explicit ButtonInput(uint8_t pin, bool activeLow = true, uint16_t longMs = 1000)
      : pin_(pin), activeLow_(activeLow), presses_(longMs) {}

  /** Call once from setup(). */
  void begin() {
    pinMode(pin_, activeLow_ ? INPUT_PULLUP : INPUT_PULLDOWN);
    delayMicroseconds(100);   // the pull resistor settles
    // Looked at twice, 50 ms apart: a hold, not a bounce.
    heldAtStart_ = down();
    if (heldAtStart_) {
      delay(50);
      heldAtStart_ = down();
    }
    portENTER_CRITICAL(&mux_);
    presses_.start(down(), millis());
    portEXIT_CRITICAL(&mux_);
    attachInterruptArg(digitalPinToInterrupt(pin_), onEdge, this, CHANGE);
  }

  /** The button was already held when begin() ran: at power-on or reset. */
  bool heldAtStart() override { return heldAtStart_; }

  /**
   * Short on release, Long as soon as the button has been held for longMs, or
   * on release if read() was not called meanwhile. Only presses that start
   * after begin() count: a button already held at power-on is never a Short
   * or a Long (heldAtStart() tells about it).
   */
  PairButton read() override {
    portENTER_CRITICAL(&mux_);
    const PairButton b = presses_.read(down(), millis());
    portEXIT_CRITICAL(&mux_);
    return b;
  }

  void clear() override {
    portENTER_CRITICAL(&mux_);
    presses_.clear();
    portEXIT_CRITICAL(&mux_);
  }

 private:
  bool down() const { return (digitalRead(pin_) == LOW) == activeLow_; }

  static void ARDUINO_ISR_ATTR onEdge(void *arg) {
    ButtonInput *b = static_cast<ButtonInput *>(arg);
    portENTER_CRITICAL_ISR(&b->mux_);
    b->presses_.edge(b->down(), millis());
    portEXIT_CRITICAL_ISR(&b->mux_);
  }

  uint8_t pin_;
  bool activeLow_;
  bool heldAtStart_ = false;
  PressDecoder presses_;
  portMUX_TYPE mux_ = portMUX_INITIALIZER_UNLOCKED;
};

}  // namespace securepair

#endif
