/*
 * SecurePair - Provisioning
 *
 * The smallest example: pairing only, one LED and one button per board.
 * Upload the same sketch to both boards.
 *
 * First start: the LED gives a short blink every 3 s.
 *   1. Press the button on both boards within a few seconds.
 *   2. Two blinks, then a countdown of three: put the LEDs face to face.
 *   3. The LEDs flicker (keys), pause 3 s, then both blink the same code of
 *      20 short and long blinks. Watch the two LEDs together.
 *   4. Same code: press the button on both boards. Different: hold it (1 s).
 *   5. Three quick blinks and a long one: saved. Fast flicker: failed.
 *
 * Later starts: one blink, and the board is ready at once. To pair again
 * (same board: new key; another board: a new peer), hold the button down
 * while each board starts, the two within about 20 s. The pairing begins at
 * step 2.
 *
 * The keys are saved in NVS, encrypted once the chip has its own key (see
 * the ChipKeySetup example). A product can refuse to work without it:
 * NvsPairStorage storage(Encryption::Required);
 *
 * Wiring: LED_ANODE_PIN -> resistor -> LED anode, LED cathode -> LED_CATHODE_PIN
 * (see PacketLED; the anode pin must be an ADC1 pin), button between
 * BUTTON_PIN and GND.
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
LedDisplay display(optical);           // code and status on the PacketLED LED
NvsPairStorage storage;                // encrypted once the chip has its key
SecurePair pairing(optical, storage, display, display);
ButtonInput button(BUTTON_PIN);

void onPairEvent(const PairEvent &e) { logPairingEvent(Serial, e); }

void setup() {
  Serial.begin(115200);
  Serial.println("\nSecurePair Provisioning: pairing over the LEDs");
  button.begin();
  led.begin();
  pairing.onEvent(onPairEvent);
  pairing.begin();
  logPairingStatus(Serial, pairing, storage.encrypted());
  pairing.provision(button);   // first start, or button held while starting: pairs now
}

void loop() {
  // Your application here: SecurePair needs nothing in loop().
}
