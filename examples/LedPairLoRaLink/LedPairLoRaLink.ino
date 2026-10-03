/*
 * SecurePair - LedPairLoRaLink
 *
 * Pair over the LEDs, then talk over LoRa: kilometers of range, with keys
 * that were agreed at a few centimeters, where nobody could get in between
 * unnoticed. Upload the same sketch to both boards. The LoRa part has not
 * been tested on hardware yet: reports are welcome.
 *
 *   - Pair as in the Provisioning example (button on both, face the LEDs,
 *     compare the blinking code, press on both).
 *   - A line typed in the Serial Monitor (115200, newline) goes to the other
 *     board; a short press sends "ping", answered with "pong".
 *
 * Needs the LoRa library by Sandeep Mistry (Library Manager: "LoRa") and an
 * SX1276/78 module. The pins below suit a TTGO LoRa32 with the PacketLED LED
 * on 32/33 and a button on 13: change them for your wiring. Use the frequency
 * allowed where you are, and mind the duty cycle.
 */

#include <LoRa.h>
#include <PacketLED.h>
#include <SPI.h>
#include <SecurePairLed.h>
#include <transport/LoRaTransport.h>

const uint8_t LED_ANODE_PIN = 32;      // ADC1 pin
const uint8_t LED_CATHODE_PIN = 33;
const uint8_t BUTTON_PIN = 13;
const uint8_t LORA_SCK = 5, LORA_MISO = 19, LORA_MOSI = 27, LORA_CS = 18, LORA_RST = 14, LORA_DIO0 = 26;
const long LORA_FREQUENCY = 868E6;

ArduinoLedPhy phy(LED_ANODE_PIN, LED_CATHODE_PIN);
PacketLED led(phy);
PacketLedTransport optical(led);       // pairing
LoRaTransport lora;                    // messages
LedDisplay display(optical);
NvsPairStorage storage;
SecurePair pairing(optical, storage, display, display);
SecureLink channel(pairing, lora);     // messages over LoRa
ButtonInput button(BUTTON_PIN);

void onPairEvent(const PairEvent &e) { logPairingEvent(Serial, e); }

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
  Serial.println("\nSecurePair LedPairLoRaLink: pairing over the LEDs, messages over LoRa");
  button.begin();
  led.begin();

  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);
  LoRa.setPins(LORA_CS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQUENCY)) Serial.println("LoRa radio not found");
  lora.begin();

  pairing.onEvent(onPairEvent);
  pairing.begin();
  logPairingStatus(Serial, pairing, storage.encrypted());
  pairing.provision(button);   // first start, or button held while starting: pairs now
  channel.sync();
}

void loop() {
  if (button.read() == PairButton::Short) sendToAll("ping");
  readSerialLine();

  char text[256];
  PeerId from;
  const int n = channel.receive((uint8_t *)text, sizeof(text) - 1, from, 5);
  if (n > 0) {
    text[n] = 0;
    Serial.printf("< %s\n", text);
    if (!strcmp(text, "ping")) channel.send(from, "pong");
  }
}
