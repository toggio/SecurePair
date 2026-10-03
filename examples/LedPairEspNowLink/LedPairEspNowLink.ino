/*
 * SecurePair - LedPairEspNowLink
 *
 * Pair over the LEDs, talk over ESP-NOW. The keys are agreed with the two
 * LEDs a few centimeters apart, where nobody can get in between unnoticed;
 * after that the radio carries only encrypted frames, over tens of meters,
 * with no aiming. Upload the same sketch to both boards.
 *
 *   - Pair as in the Provisioning example (button on both, face the LEDs,
 *     compare the blinking code, press on both).
 *   - Then move the boards apart. A short press makes the other board's LED
 *     play a quick light show; when it answers, this board's LED blinks twice.
 *     No computer needed to see the link work.
 *   - A line typed in the Serial Monitor (115200, newline) goes to the other board.
 *
 * Wiring: LED_ANODE_PIN -> resistor -> LED anode, LED cathode -> LED_CATHODE_PIN
 * (the anode pin must be an ADC1 pin), button between BUTTON_PIN and GND.
 */

#include <PacketLED.h>
#include <SecurePairLed.h>
#include <transport/EspNowTransport.h>

// Defaults for the ESP32 and the ESP32-C3/C6. On other chips, pick an ADC1 pin
// for the anode and a button pin that is not a boot strapping pin.
#if CONFIG_IDF_TARGET_ESP32
const uint8_t LED_ANODE_PIN = 32, LED_CATHODE_PIN = 33, BUTTON_PIN = 13;
#else
const uint8_t LED_ANODE_PIN = 0, LED_CATHODE_PIN = 1, BUTTON_PIN = 3;
#endif

ArduinoLedPhy phy(LED_ANODE_PIN, LED_CATHODE_PIN);
PacketLED led(phy);
PacketLedTransport optical(led);       // pairing
EspNowTransport radio;                 // messages
LedDisplay display(optical);
NvsPairStorage storage;
SecurePair pairing(optical, storage, display, display);
SecureLink channel(pairing, radio);    // messages over the radio
ButtonInput button(BUTTON_PIN);

void onPairEvent(const PairEvent &e) { logPairingEvent(Serial, e); }

void blinkLed(int times, uint32_t onMs, uint32_t offMs) {
  for (int i = 0; i < times; ++i) {
    led.setLed(true);
    delay(onMs);
    led.setLed(false);
    delay(offMs);
  }
}

void lightShow() {
  for (uint32_t ms = 10; ms <= 90; ms += 10) blinkLed(1, ms, 100 - ms);   // longer and longer flashes
  blinkLed(6, 30, 30);
}

// Sends to every paired board.
void sendToAll(const char *text) {
  PeerInfo peer;
  for (size_t i = 0; pairing.peerInfo(i, peer); ++i)
    Serial.printf("> %s  [%s]\n", text, SecureLink::resultText(channel.send(peer.id, text)));
}

void readSerialLine() {
  static char line[128];
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
  Serial.println("\nSecurePair LedPairEspNowLink: pairing over the LEDs, messages over ESP-NOW");
  button.begin();
  led.begin();
  pairing.onEvent(onPairEvent);
  pairing.begin();
  logPairingStatus(Serial, pairing, storage.encrypted());
  pairing.provision(button);   // first start, or button held while starting: pairs now
  radio.begin();   // after the pairing: Wi-Fi would disturb the LEDs
  channel.sync();
}

void loop() {
  if (button.read() == PairButton::Short) sendToAll("FX");
  readSerialLine();

  char text[256];
  PeerId from;
  const int n = channel.receive((uint8_t *)text, sizeof(text) - 1, from, 5);
  if (n <= 0) return;
  text[n] = 0;
  if (!strcmp(text, "FX")) {
    Serial.println("< FX: light show, then OK back");
    lightShow();
    channel.send(from, "OK");
  } else if (!strcmp(text, "OK")) {
    Serial.println("< OK: the other board played it");
    blinkLed(2, 100, 100);
  } else {
    Serial.printf("< %s\n", text);
  }
}
