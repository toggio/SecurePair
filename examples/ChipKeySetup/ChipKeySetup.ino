/*
 * SecurePair - ChipKeySetup
 *
 * Writes the chip's own key: 256 random bits in an eFuse key block, which only
 * the chip's HMAC peripheral can use. Run it once on each board; from then on
 * NvsPairStorage, in any SecurePair sketch, saves the pairings encrypted with
 * it. A board that was already paired starts over: what it saved in clear is
 * erased, and it pairs again.
 *
 * Writing eFuses cannot be undone. The block (KEY5, unless it is taken) can
 * never be erased or used for anything else; the others stay free for flash
 * encryption and secure boot. The key is never shown or saved anywhere else:
 * once written, only the HMAC peripheral can use it.
 *
 * Commands in the Serial Monitor (115200, newline):
 *   status   the six key blocks and what they hold
 *   check    whether SecurePair can use the key, and its fingerprint
 *   burn     writes the key, after a typed confirmation
 *
 * Needs a chip with an HMAC peripheral: ESP32-S2, S3, C3, C5, C6, H2 or P4.
 */

#include <SecurePair.h>
#include <storage/HmacChipKey.h>

#if !SOC_HMAC_SUPPORTED
#error "ChipKeySetup needs a chip with an HMAC peripheral: ESP32-S2, S3, C3, C5, C6, H2 or P4. On the original ESP32, use flash encryption with NVS encryption instead."
#endif

#include <bootloader_random.h>
#include <esp_efuse.h>
#include <esp_random.h>

using namespace securepair;

HmacChipKey chipKey;

// One line from the Serial Monitor, without the line ending. Waits for it.
String readLine() {
  while (!Serial.available()) delay(10);
  String line = Serial.readStringUntil('\n');
  line.trim();
  return line;
}

const char *purposeName(esp_efuse_purpose_t p) {
  switch (p) {
    case ESP_EFUSE_KEY_PURPOSE_USER: return "USER";
    case ESP_EFUSE_KEY_PURPOSE_XTS_AES_128_KEY: return "XTS_AES_128_KEY (flash encryption)";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_ALL: return "HMAC_DOWN_ALL";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_JTAG: return "HMAC_DOWN_JTAG";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE: return "HMAC_DOWN_DIGITAL_SIGNATURE";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_UP: return "HMAC_UP";
    case ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0: return "SECURE_BOOT_DIGEST0";
    case ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1: return "SECURE_BOOT_DIGEST1";
    case ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2: return "SECURE_BOOT_DIGEST2";
    default: return "another purpose";
  }
}

void status() {
  const int inUse = chipKey.block();
  Serial.printf("\n%s\n", ESP.getChipModel());
  for (int i = 0; i < 6; ++i) {
    const esp_efuse_block_t b = (esp_efuse_block_t)(EFUSE_BLK_KEY0 + i);
    Serial.printf("KEY%d  ", i);
    if (esp_efuse_key_block_unused(b)) {
      Serial.println("free");
      continue;
    }
    Serial.printf("%s, %s%s%s\n", purposeName(esp_efuse_get_key_purpose(b)),
                  esp_efuse_get_key_dis_read(b) ? "read-protected" : "readable",
                  esp_efuse_get_key_dis_write(b) ? ", write-protected" : "",
                  i == inUse ? "   <- SecurePair chip key" : "");
  }
}

void check() {
  const int i = chipKey.block();
  if (i < 0) {
    esp_efuse_block_t b;
    if (esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &b))
      Serial.printf("KEY%d holds an HMAC_UP key, but it is readable: not a secret, so "
                    "SecurePair ignores it.\n", (int)(b - EFUSE_BLK_KEY0));
    else
      Serial.println("This chip has no key yet: type burn to write one.");
    return;
  }

  // An HMAC of a fixed text: always the same on this board, different on any
  // other, and it tells nothing about the key.
  static const char kLabel[] = "SecurePair fingerprint";
  uint8_t mac[32];
  if (!chipKey.derive(kLabel, sizeof(kLabel) - 1, mac)) {
    Serial.println("The HMAC peripheral did not answer.");
    return;
  }
  Serial.printf("Chip key in KEY%d, read-protected: SecurePair can use it.\n", i);
  Serial.printf("Fingerprint: %02X%02X-%02X%02X-%02X%02X-%02X%02X\n", mac[0], mac[1], mac[2],
                mac[3], mac[4], mac[5], mac[6], mac[7]);
}

void burn() {
  if (chipKey.available()) {
    Serial.println("This chip already has its key.");
    check();
    return;
  }
  int n = -1;   // KEY5, or the highest free block
  for (int i = 5; i >= 0 && n < 0; --i)
    if (esp_efuse_key_block_unused((esp_efuse_block_t)(EFUSE_BLK_KEY0 + i))) n = i;
  if (n < 0) {
    Serial.println("No free key block: all six are in use.");
    return;
  }

  char confirm[12];
  snprintf(confirm, sizeof(confirm), "BURN KEY%d", n);
  Serial.printf("\nThis writes a random 256-bit key into KEY%d, for the HMAC peripheral.\n"
                "It cannot be undone: the block can never be erased or used for anything else.\n"
                "The key is never shown: once written, only the HMAC peripheral can use it.\n"
                "From the next start pairings are saved encrypted, and those in clear are\n"
                "erased: this board will pair again.\n"
                "Type %s to go on, anything else to cancel.\n", n, confirm);
  if (readLine() != confirm) {
    Serial.println("Cancelled.");
    return;
  }

  // With the radio off, the ADC noise makes the generator truly random.
  uint8_t key[32];
  bootloader_random_enable();
  esp_fill_random(key, sizeof(key));
  bootloader_random_disable();

  // Key, purpose and protection bits are written in one batch.
  const esp_err_t err = esp_efuse_write_key((esp_efuse_block_t)(EFUSE_BLK_KEY0 + n),
                                            ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
  volatile uint8_t *p = key;   // the only copy outside the eFuses
  for (size_t i = 0; i < sizeof(key); ++i) p[i] = 0;
  if (err != ESP_OK) {
    Serial.printf("Writing failed: %s\n", esp_err_to_name(err));
    return;
  }
  Serial.println("Written.");
  check();
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000) delay(10);   // native USB: wait for the Serial Monitor
  Serial.println("\nSecurePair ChipKeySetup. Commands: status, check, burn");
  status();
  check();
}

void loop() {
  if (!Serial.available()) return;
  String command = readLine();
  command.toLowerCase();
  if (command == "status") status();
  else if (command == "check") check();
  else if (command == "burn") burn();
  else if (command.length()) Serial.println("Commands: status, check, burn");
}
