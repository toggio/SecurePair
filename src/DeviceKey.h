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
 * A secret that the program can use but not read.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace securepair {

/**
 * derive() returns HMAC-SHA256(secret, message); the secret itself never
 * reaches the program. NvsPairStorage takes its key from here, so what it
 * saves on one board cannot be read on another.
 *
 * HmacChipKey keeps the secret in an eFuse block of the chip. Another
 * implementation could use a secure element.
 */
class DeviceKey {
 public:
  virtual ~DeviceKey() {}

  /** Whether the secret is there, checked without using it. */
  virtual bool available() = 0;

  /** @return false if there is no key, or the calculation failed. */
  virtual bool derive(const void *message, size_t len, uint8_t out[32]) = 0;
};

}  // namespace securepair
