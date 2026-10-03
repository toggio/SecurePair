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
 * The chip's own key, in an eFuse block, used through the HMAC peripheral.
 */

#pragma once

#include <soc/soc_caps.h>

#if SOC_HMAC_SUPPORTED

#include <esp_efuse.h>
#include <esp_hmac.h>

#include "../DeviceKey.h"

namespace securepair {

/**
 * A 256-bit key written once into an eFuse key block, with purpose HMAC_UP,
 * by the ChipKeySetup example. The block is read-protected: neither a program
 * nor a tool over USB can read it back, and only the HMAC peripheral uses it.
 *
 * This class only uses the key. It never writes eFuses.
 *
 * Chips with an HMAC peripheral: ESP32-S2, S3, C3, C5, C6, H2 and P4, not the
 * original ESP32.
 */
class HmacChipKey : public DeviceKey {
 public:
  /**
   * The key block in use, 0 to 5 for KEY0 to KEY5, or -1 if there is none.
   * A readable key is not a secret and is ignored. The search starts from
   * KEY5, where ChipKeySetup writes.
   */
  int block() const {
    for (int i = EFUSE_BLK_KEY_MAX - 1; i >= EFUSE_BLK_KEY0; --i) {
      const esp_efuse_block_t b = (esp_efuse_block_t)i;
      if (esp_efuse_get_key_purpose(b) == ESP_EFUSE_KEY_PURPOSE_HMAC_UP &&
          esp_efuse_get_key_dis_read(b))
        return i - EFUSE_BLK_KEY0;
    }
    return -1;
  }

  bool available() override { return block() >= 0; }

  bool derive(const void *message, size_t len, uint8_t out[32]) override {
    const int i = block();
    return i >= 0 &&
           esp_hmac_calculate((hmac_key_id_t)(HMAC_KEY0 + i), message, len, out) == ESP_OK;
  }
};

}  // namespace securepair

#endif
