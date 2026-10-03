/*
 * SecurePair - EspNowOnly
 *
 * Pairing and encrypted messages over ESP-NOW: no wiring but a button.
 * Upload the same sketch to both boards.
 *
 *   1. Press the button on both boards within a few seconds.
 *   2. Both LEDs blink the same code, and both Serial Monitors print it as
 *      six digits. Same code: press on both. Different: hold the button (1 s).
 *   3. A line typed in the Serial Monitor (115200, newline) goes, encrypted,
 *      to the other board.
 *   4. To pair again later, hold the button down while each board starts.
 *
 * ESP-NOW reaches tens of meters: anybody in range could try to sit in the
 * middle, and comparing the code is what stops them. Compare it for real.
 *
 * STATUS_LED is the board's LED (LED_BUILTIN). Set it to your LED's pin if
 * the board has none defined.
 */

#include <SecurePair.h>
#include <SecureLink.h>
#include <storage/NvsPairStorage.h>
#include <transport/EspNowTransport.h>
#include <ui/ButtonInput.h>
#include <ui/GpioLedSink.h>
#include <ui/LedDisplay.h>
#include <ui/PairingLog.h>

using namespace securepair;

// Defaults for the ESP32 and the ESP32-C3/C6. On other chips, any free pin
// that is not a boot strapping pin.
#if CONFIG_IDF_TARGET_ESP32
const uint8_t BUTTON_PIN = 13;
#else
const uint8_t BUTTON_PIN = 3;
#endif
#ifdef LED_BUILTIN
const uint8_t STATUS_LED = LED_BUILTIN;
#else
const uint8_t STATUS_LED = 2;          // set your board's LED pin
#endif

EspNowTransport radio;
GpioLedSink statusLed(STATUS_LED);
LedDisplay display(statusLed);
NvsPairStorage storage;
SecurePair pairing(radio, storage, display, display);
SecureLink channel(pairing);
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
  Serial.println("\nSecurePair EspNowOnly: pairing and messages over ESP-NOW");
  button.begin();
  statusLed.begin();
  radio.begin();

  pairing.onEvent(onPairEvent);
  pairing.begin(PairConfig::forRadio());   // shorter pauses than with LEDs
  logPairingStatus(Serial, pairing, storage.encrypted());
  pairing.provision(button);   // first start, or button held while starting: pairs now
  channel.sync();
}

void loop() {
  readSerialLine();
  char text[256];
  PeerId from;
  const int n = channel.receive((uint8_t *)text, sizeof(text) - 1, from);
  if (n > 0) {
    text[n] = 0;
    Serial.printf("< %s\n", text);
  }
}
