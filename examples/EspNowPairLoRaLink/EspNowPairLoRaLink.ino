/*
 * SecurePair - EspNowPairLoRaLink
 *
 * Pair over ESP-NOW, then talk over LoRa. Pairing needs the two boards near
 * each other and a user comparing their LEDs; the messages then travel for
 * kilometers, encrypted. Upload the same sketch to both boards. The LoRa part
 * has not been tested on hardware yet: reports are welcome.
 *
 *   1. Press the button on both boards within a few seconds.
 *   2. Both LEDs blink the same code, and both Serial Monitors print it as six
 *      digits. Same code: press on both. Different: hold the button (1 s).
 *   3. A line typed in the Serial Monitor (115200, newline) goes to the other
 *      board over LoRa; a short press sends "ping", answered with "pong".
 *   4. To pair again later, hold the button down while each board starts.
 *
 * Needs the LoRa library by Sandeep Mistry (Library Manager: "LoRa") and an
 * SX1276/78 module. The pins below suit a TTGO LoRa32 with a button on 13:
 * change them for your board. Use the frequency allowed where you are, and
 * mind the duty cycle. STATUS_LED is the board's LED (LED_BUILTIN); set it to
 * your LED's pin if the board has none defined.
 */

#include <LoRa.h>
#include <SPI.h>
#include <SecureLink.h>
#include <SecurePair.h>
#include <storage/NvsPairStorage.h>
#include <transport/EspNowTransport.h>
#include <transport/LoRaTransport.h>
#include <ui/ButtonInput.h>
#include <ui/GpioLedSink.h>
#include <ui/LedDisplay.h>
#include <ui/PairingLog.h>

using namespace securepair;

const uint8_t BUTTON_PIN = 13;
#ifdef LED_BUILTIN
const uint8_t STATUS_LED = LED_BUILTIN;
#else
const uint8_t STATUS_LED = 25;         // set your board's LED pin
#endif
const uint8_t LORA_SCK = 5, LORA_MISO = 19, LORA_MOSI = 27, LORA_CS = 18, LORA_RST = 14, LORA_DIO0 = 26;
const long LORA_FREQUENCY = 868E6;

EspNowTransport radio;                 // pairing
LoRaTransport lora;                    // messages
GpioLedSink statusLed(STATUS_LED);
LedDisplay display(statusLed);
NvsPairStorage storage;
SecurePair pairing(radio, storage, display, display);
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
  Serial.println("\nSecurePair EspNowPairLoRaLink: pairing over ESP-NOW, messages over LoRa");
  button.begin();
  statusLed.begin();

  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);
  LoRa.setPins(LORA_CS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQUENCY)) Serial.println("LoRa radio not found");
  lora.begin();
  radio.begin();

  pairing.onEvent(onPairEvent);
  pairing.begin(PairConfig::forRadio());   // shorter pauses than with LEDs
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
