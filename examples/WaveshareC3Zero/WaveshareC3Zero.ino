/*
 * SecurePair - WaveshareC3Zero
 *
 * For the Waveshare ESP32-C3-Zero, which has a WS2812 RGB LED on GPIO10.
 * The same as LedOnly, with the code and the status on the RGB LED: pairing
 * and messages over the PacketLED LEDs, no radio. Upload the same sketch to
 * both boards.
 *
 * The RGB LED shows everything, no Serial needed:
 *   - not paired: short blue blink every 3 s. Press the button on both boards,
 *     face the PacketLED LEDs during the blue countdown, then compare the code
 *     on the two RGB LEDs: 20 short and long blinks in four colors.
 *     Same: press on both. Different: hold the button.
 *   - paired: keep the PacketLED LEDs facing each other. A short press makes
 *     the other board play a rainbow, then answer; a green flash here means
 *     the round trip worked.
 *   - to pair again, hold the button down while each board starts.
 *
 * A line typed in the Serial Monitor (115200, newline) goes to the other board,
 * up to 35 bytes. Enable "USB CDC On Boot" to use the Serial Monitor.
 *
 * Wiring: GPIO0 -> resistor -> LED anode, LED cathode -> GPIO1 (see PacketLED),
 * button between GPIO3 and GND.
 */

#include <PacketLED.h>
#include <SecurePairLed.h>

#if !CONFIG_IDF_TARGET_ESP32C3
#error "WaveshareC3Zero is for the Waveshare ESP32-C3-Zero: select an ESP32-C3 board. On other boards, start from LedOnly."
#endif

const uint8_t LED_ANODE_PIN = 0;
const uint8_t LED_CATHODE_PIN = 1;
const uint8_t BUTTON_PIN = 3;
const uint8_t RGB_PIN = 10;
const rgb_led_color_order_t RGB_ORDER = LED_COLOR_ORDER_RGB;   // red and green are swapped on this board

ArduinoLedPhy phy(LED_ANODE_PIN, LED_CATHODE_PIN);
PacketLED led(phy);
PacketLedTransport optical(led);       // pairing and messages
RgbLedDisplay rgb(RGB_PIN, 40, RGB_ORDER);
NvsPairStorage storage;
SecurePair pairing(optical, storage, rgb, rgb);
SecureLink channel(pairing);           // messages over the pairing transport
ButtonInput button(BUTTON_PIN);

void onPairEvent(const PairEvent &e) { logPairingEvent(Serial, e); }

Rgb wheel(uint8_t pos) {   // hue 0-255 -> color
  if (pos < 85) return Rgb{(uint8_t)(255 - pos * 3), (uint8_t)(pos * 3), 0};
  if (pos < 170) {
    pos -= 85;
    return Rgb{0, (uint8_t)(255 - pos * 3), (uint8_t)(pos * 3)};
  }
  pos -= 170;
  return Rgb{(uint8_t)(pos * 3), 0, (uint8_t)(255 - pos * 3)};
}

void rainbow() {
  for (int i = 0; i < 512; i += 4) {
    rgb.set(wheel((uint8_t)i));
    delay(6);
  }
  rgb.off();
}

void flash(Rgb c, uint32_t ms) {
  rgb.set(c);
  delay(ms);
  rgb.off();
}

// Sends to every paired board.
void sendToAll(const char *text) {
  PeerInfo peer;
  for (size_t i = 0; pairing.peerInfo(i, peer); ++i)
    Serial.printf("> %s  [%s]\n", text, SecureLink::resultText(channel.send(peer.id, text)));
}

void readSerialLine() {
  static char line[36];                // 35 bytes: the most a PacketLED message carries
  static size_t len = 0;
  while (Serial.available()) {
    const char c = Serial.read();
    if (c == '\n') {
      line[len] = 0;
      if (len) sendToAll(line);
      len = 0;
    } else if (c != '\r' && len < sizeof(line) - 1) {
      line[len++] = c;
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.println("\nSecurePair WaveshareC3Zero: pairing and messages over the LEDs");
  button.begin();
  rgb.off();
  led.begin();
  pairing.onEvent(onPairEvent);
  pairing.begin();
  logPairingStatus(Serial, pairing, storage.encrypted());
  pairing.provision(button);   // first start, or button held while starting: pairs now
  channel.sync();   // after a reset: no message from the other board is refused
}

void loop() {
  if (button.read() == PairButton::Short) sendToAll("FX");
  readSerialLine();

  char text[64];
  PeerId from;
  const int n = channel.receive((uint8_t *)text, sizeof(text) - 1, from);
  if (n <= 0) return;
  text[n] = 0;
  if (!strcmp(text, "FX")) {
    Serial.println("< FX: rainbow, then OK back");
    rainbow();
    channel.send(from, "OK");
  } else if (!strcmp(text, "OK")) {
    Serial.println("< OK: the other board played it");
    flash(Rgb{0, 255, 0}, 150);
  } else {
    Serial.printf("< %s\n", text);
  }
}
