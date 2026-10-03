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
 * Record names shared by the two NVS formats (PlainNvsStorage, SealedNvsStorage).
 */

#pragma once

#include <stddef.h>

namespace securepair {
namespace nvs {

constexpr size_t kMaxSlots = 16;

/** One peer slot: "p00".."p15" in clear, "s00".."s15" sealed. */
inline void slotName(char prefix, size_t slot, char name[4]) {
  name[0] = prefix;
  name[1] = (char)('0' + slot / 10);
  name[2] = (char)('0' + slot % 10);
  name[3] = 0;
}

}  // namespace nvs
}  // namespace securepair
