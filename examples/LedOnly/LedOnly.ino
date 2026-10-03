/*
 * SecurePair - LedOnly
 *
 * Pairing and encrypted messages over the same LEDs: nothing but one LED and
 * one button per board. Upload the same sketch to both boards, pair them as in
 * the Provisioning example, then keep the LEDs facing each other:
 *   - a line typed in the Serial Monitor (115200, newline) goes to the other board;
 *   - a short press sends "ping", and the other board answers "pong".
 *
 * Messages carry up to 35 bytes over PacketLED.
 *
 * Wiring: LED_ANODE_PIN -> resistor -> LED anode, LED cathode -> LED_CATHODE_PIN
 * (the anode pin must be an ADC1 pin), button between BUTTON_PIN and GND.
 */

#include <PacketLED.h>
#include <SecurePairLed.h>

// Defaults for the ESP32 and the ESP32-C3/C6. On other chips, pick an ADC1 pin
// for the anode and a button pin that is not a boot strapping pin.
#if CONFIG_IDF_TARGET_ESP32
const uint8_t LED_ANODE_PIN = 32, LED_CATHODE_PIN = 33, BUTTON_PIN = 13;
#else
const uint8_t LED_ANODE_PIN = 0, LED_CATHODE_PIN = 1, BUTTON_PIN = 3;
#endif

ArduinoLedPhy phy(LED_ANODE_PIN, LED_CATHODE_PIN);
PacketLED led(phy);
PacketLedTransport optical(led);
LedDisplay display(optical);
NvsPairStorage storage;
SecurePair pairing(optical, storage, display, display);
SecureLink channel(pairing);           // messages over the pairing transport
ButtonInput button(BUTTON_PIN);

void onPairEvent(const PairEvent &e) { logPairingEvent(Serial, e); }

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
  Serial.println("\nSecurePair LedOnly: pairing and messages over the LEDs");
  button.begin();
  led.begin();
  pairing.onEvent(onPairEvent);
  pairing.begin();
  logPairingStatus(Serial, pairing, storage.encrypted());
  pairing.provision(button);   // first start, or button held while starting: pairs now
  channel.sync();   // after a reset: no message from the other board is refused
}

void loop() {
  if (button.read() == PairButton::Short) sendToAll("ping");
  readSerialLine();

  char text[64];
  PeerId from;
  const int n = channel.receive((uint8_t *)text, sizeof(text) - 1, from);
  if (n > 0) {
    text[n] = 0;
    Serial.printf("< %s\n", text);
    if (!strcmp(text, "ping")) channel.send(from, "pong");
  }
}
