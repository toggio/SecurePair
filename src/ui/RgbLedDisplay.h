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
 * Status patterns and code on a WS2812 RGB LED, on any pin (GPIO10 on the
 * Waveshare ESP32-C3-Zero, GPIO8 on many C3/C6 DevKits).
 *
 * Use it as CodeDisplay, as StatusDisplay, or both. The code keeps the timing
 * of LedDisplay (short = 0, long = 1), so it can be compared with a board that
 * blinks a plain LED. Each blink also gets one of four colors, taken from the
 * next two bits of the same code: a difference between two codes then shows up
 * in several blinks at once. Between pairings the application may use the LED
 * with set().
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>

#include "../PairDisplay.h"

namespace securepair {

struct Rgb {
  uint8_t r, g, b;
};

class RgbLedDisplay : public CodeDisplay, public StatusDisplay {
 public:
  /**
   * @param brightness 0-255, scales every color
   * @param order      LED_COLOR_ORDER_GRB for most WS2812; some boards swap red and green
   */
  explicit RgbLedDisplay(uint8_t pin, uint8_t brightness = 40,
                         rgb_led_color_order_t order = LED_COLOR_ORDER_GRB)
      : pin_(pin), brightness_(brightness), order_(order) {}

  void set(Rgb c);
  void off() { set(Rgb{0, 0, 0}); }

  void show(const PairCode &code, uint32_t startUs, uint32_t durationMs) override;
  void play(StatusPattern pattern) override;

  // Colors, changeable before use.
  Rgb info = {0, 0, 255};        // armed, countdown, not paired
  Rgb ask = {255, 160, 0};       // waiting for the user's confirmation
  Rgb good = {0, 255, 0};        // ready, saved
  Rgb bad = {255, 0, 0};         // error
  Rgb codeColors[4] = {{0, 80, 255}, {0, 255, 60}, {255, 200, 0}, {255, 0, 200}};   // no red: it means error

 private:
  void blink(Rgb c, uint32_t onMs, uint32_t offMs);

  uint8_t pin_;
  uint8_t brightness_;
  rgb_led_color_order_t order_;
};

}  // namespace securepair

#endif
