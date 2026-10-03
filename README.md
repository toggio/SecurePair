# SecurePair

Cryptographically secure pairing and communication between ESP32 boards: pair through a single standard LED with the LX.25 protocol, or over ESP-NOW and LoRa.

The keys are agreed with an elliptic-curve exchange (X25519), and the messages are encrypted with AES-256-GCM. The library does not depend on the medium: it works over ESP-NOW, LoRa or anything else that moves packets, and even through a single standard red LED per board, with the [PacketLED](https://github.com/toggio/PacketLED) library.

Pairing takes a button on each board and a person who compares a short code. There is no app, no QR code, no password and no key baked into the firmware.

- **Keys through light.** With [PacketLED](https://github.com/toggio/PacketLED) the same LED sends, receives and shows the code. No radio signal goes out, and to get in between, an attacker would have to reach both LEDs with its own light, in front of you. Even then, the code gives it away.
- **Checked by a person.** Both boards blink the same 20-step code, in step. A device in the middle cannot make the two codes match, except by a one-in-a-million chance.
- **Many boards, not just two.** Every board has its own permanent identity and keeps up to 8 peers, each with its own key. Pairing again with a board it already knows replaces that board's key, only once both sides have confirmed.
- **Then any medium.** After pairing, messages travel encrypted and authenticated over the same LEDs, over ESP-NOW (tens of meters) or over LoRa (kilometers), or over a transport of your own. No LEDs at hand? The pairing itself can run over the radio too.
- **Standard cryptography.** X25519, HKDF and AES-256-GCM, the building blocks of TLS 1.3, with replay protection. The pairing keys survive resets, and can be stored encrypted with a key kept in the chip itself.
- **Little code.** `provision()` in `setup()`, then `send()` and `receive()` for the messages. Nothing for the pairing in `loop()`.

**Status: beta (0.5).**

- Tested on hardware, on ESP32, ESP32-C3 and ESP32-C6 boards: pairing over the LEDs (up to 2 m apart) and over ESP-NOW, messages over the LEDs and over ESP-NOW, pairing again with the button held at start, and the encrypted storage.
- Not yet tried on hardware: LoRa.
- Meant to stay: the core idea, a key agreed once, confirmed by a person, then used over any medium.
- Meant to grow: the transports and displays around it. Test reports and contributions are welcome.

**Contents:** [What it does](#what-it-does) · [Why light](#why-light) · [Use cases](#use-cases) · [What the user sees](#what-the-user-sees) · [Cryptography](#cryptography) · [Installation](#installation) · [Usage](#usage) · [Transports](#transports) · [Examples](#examples) · [Troubleshooting](#troubleshooting) · [Limitations](#limitations) · [Related work](#related-work)

## What it does

Two boards that talk to each other need a shared secret key. Without one, anybody within range can read their messages or send fake ones. Getting that key onto both boards safely is the awkward part. Written into the firmware, it is the same on every device, and anyone who gets hold of one board has it. Typed in, it needs a keyboard and a screen.

SecurePair handles the whole job, from the pairing to the messages:

- the boards agree on a fresh key between themselves, and the user confirms it by comparing a short code;
- the key is saved, with the identity of the other board, and survives resets;
- messages are encrypted, authenticated and protected against replay, over the same medium used for pairing or another one.

## Why light

SecurePair does not care how the packets travel. The medium is a small interface, and the library comes with PacketLED, ESP-NOW and LoRa. It was designed around light, though, and pairing with PacketLED is where it gives the most.

- Light is hard to reach. It does not go through walls, and PacketLED works between two LEDs pointed at each other, a few centimeters apart during pairing. Listening in gains nothing, since the key exchange is safe to watch, and getting in the middle means reaching both LEDs with a sensor and a light of its own, in front of the user. A radio pairing can be attacked by anybody within tens of meters, without being seen. Over light or radio, what catches a device in the middle is the code the user compares; the light makes the attempt much harder to set up.
- Nothing is radiated. While the keys are agreed there is no radio signal to pick up or jam.
- The code is shown by the LED that carried the keys. Each board blinks the code on its own PacketLED LED, 20 short and long blinks in step with the other board. The user watches the two LEDs side by side, and a difference stands out at once. There is nothing to read or type.
- One LED and one resistor per board, with no extra chip. The same LED also works as the device's status light.

The code comparison is what secures any pairing, whatever the medium. Light adds physical closeness on top of it and makes the comparison easier. After pairing, the messages can go over the same LEDs (short range, 35 bytes each) or over a radio.

## Use cases

- Sensor nodes and a gateway. Pair each node with the gateway on the desk, LED to LED, then install it. Readings travel encrypted over ESP-NOW or LoRa, and a fake node cannot inject data.
- Remote controls and actuators, such as a relay, a gate opener or a lock. Commands are authenticated and accepted once, so a recorded command cannot be played back later.
- Devices with no screen or keyboard. An LED and a button are enough to set up a key, holding the device against the controller.
- Replacing a board in the field. A new board pairs on its first start, and a board that already has peers pairs with it when started with the button held, or at any time if the application allows it. An interrupted pairing leaves the existing keys in place.
- One hub with several devices. Each board keeps up to 8 peers, each with its own key.
- Learning. A small, readable implementation of key agreement, short authentication strings and authenticated encryption, with tests that run on a PC.

## What the user sees

1. Press the button on both boards within a few seconds.
2. Two blinks, then a countdown of three: put the LEDs face to face.
3. The LEDs flicker while the boards exchange keys, pause, then blink the same code together: 20 short and long blinks.
4. Same code: press on both boards. Different: hold the button on either.
5. Three quick blinks and a long one: saved. A fast flicker: failed, and nothing changed.

To pair again later, with a new key or with another board, hold the button down while you power on or reset each board, the two within about 20 s. The pairing starts at step 2. Without the button, the board starts at once, as usual.

A short press during the code does not count, because whoever presses before the end has not watched all of it; a long one rejects as soon as the code ends. With an RGB LED each blink also has a color, so a difference shows in several blinks at once. Without LEDs the code can be printed as six digits.

## What is included

| | |
|---|---|
| Transports | PacketLED (one LED), ESP-NOW, LoRa (SX1276/78, not tested yet) |
| Code display | a plain LED, a WS2812 RGB LED, six digits on any `Print` |
| Status display | a plain LED, a WS2812 RGB LED |
| Input | a push button (short and long press) |
| Storage | ESP32 NVS, in clear or encrypted with a key that never leaves the chip |

- Several peers per board. Each board keeps up to 8 peers (up to 16 if configured) and recognizes a board it has already paired with: a new pairing then replaces that board's key instead of adding a second record.
- Safe key replacement. The old key stays valid until both boards have saved the new one, and the next pairing settles anything an earlier one left pending. A re-pairing cut short by lost packets or a power failure leaves the boards talking with the old key or the new one; [PROTOCOL.md](docs/PROTOCOL.md#84-failures) goes through each case.
- Quiet the rest of the time. Outside a pairing SecurePair runs no code of its own, and `loop()` calls none of it. To pair again, hold the button down while the board starts, or start the pairing from the application.
- Everything is an interface. Transports, displays, input and storage can be replaced, as [EXTENDING.md](EXTENDING.md) shows.

## Cryptography

Standard, well-studied primitives only:

| Purpose | Algorithm | Standard |
|---|---|---|
| Key agreement | X25519 (Curve25519 Diffie-Hellman) | RFC 7748 |
| Hashing, commitments, transcript | SHA-256 | FIPS 180-4 |
| Authentication of pairing messages | HMAC-SHA256 | RFC 2104 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Message encryption and authentication | AES-256-GCM | FIPS 197, NIST SP 800-38D |

X25519 and AES-GCM come from Mbed TLS, as shipped with the ESP32 core, and use the ESP32's hardware AES. SHA-256, HMAC and HKDF are implemented in the library and checked against reference values, on the PC and on the board (CryptoSelfTest).

How they are put together:

- **Pairing.** Each pairing uses fresh X25519 keys. One board commits to its key with a hash before seeing the other's, so nobody can choose a key after the fact to make the two codes match. That is what lets a 20-bit code (one chance in 1,048,576 per attempt) be enough, the same idea as Bluetooth numeric comparison.
- **Identity.** Each board also has a permanent identity key. The identities travel encrypted during pairing, and a second Diffie-Hellman between them goes into the saved key, so each board proves it holds its own identity.
- **Transcript.** Everything exchanged, including the protocol version, is hashed into the keys through HKDF. A message changed along the way, or a downgrade, gives different keys, and the pairing fails.
- **Confirmation.** Both confirmations are authenticated (HMAC). A board saves the new key only after the other user has confirmed too, and drops the old one only once the other board sends with the new one.
- **Messages.** Each direction has its own AES-256-GCM key, derived from the saved one. The 96-bit nonce is a boot counter kept in flash plus a message counter, so it is never repeated, even across resets. Every message carries a 128-bit tag. The receiver accepts each message once, and after its own reset checks with a challenge that a message is not a replay.
- **Keys at rest.** Once the chip has its own eFuse key, `NvsPairStorage` encrypts every saved record with AES-256-GCM. The storage key is derived with HKDF from an HMAC that the chip's HMAC peripheral computes with the eFuse key. A record cannot be read, changed or moved to another slot or board, and deleting one only makes the board forget.
- **Hygiene.** Tags are compared in constant time, invalid (low-order) keys are refused, and temporary keys are wiped from RAM after use. Random numbers come from the ESP32's generator, mixed with noise read from the LED through SHA-256.

What it does not protect:

- A user who confirms without looking.
- Someone who reads the flash of a board. Without a chip key they get its pairing keys. With one, they get nothing useful, unless they can also run their own code on the same chip (see [Keys stored encrypted](#keys-stored-encrypted)).
- Messages recorded earlier, since there is no forward secrecy. The message key is stored, so whoever later reads it can decrypt messages recorded before. Pairing again replaces the key.

The protocol has not yet been reviewed by an independent cryptographer. [PROTOCOL.md](docs/PROTOCOL.md) describes it in full, including every failure case, to make that review possible. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Requirements

- An ESP32 board with the Arduino-ESP32 core 3.x. Compiled for the ESP32, ESP32-C3 and ESP32-C6 with core 3.3.12. The encrypted storage needs a chip with an HMAC peripheral: ESP32-S2, S3, C3, C5, C6, H2 or P4.
- A push button, or any other way to say "yes" and "no". Do not put the button on a boot strapping pin such as BOOT: held during a reset, that pin starts the download mode instead of the sketch.
- For pairing with light, the [PacketLED](https://github.com/toggio/PacketLED) library, 1.1.0 or later, and one LED with a resistor per board. For LoRa, the [LoRa](https://github.com/sandeepmistry/arduino-LoRa) library by Sandeep Mistry.

## Installation

In the Arduino IDE, open the Library Manager, search for **SecurePair** and click *Install*. The IDE offers to install PacketLED with it; add LoRa too if you need it.

With PlatformIO, add the library to `platformio.ini`; PacketLED comes with it:

```ini
lib_deps = toggio/SecurePair
```

You can also download the repository as a ZIP file and add it with *Sketch > Include Library > Add .ZIP Library*.

## Usage

### Pairing with light, messages over ESP-NOW

Two ESP32 boards, each with an LED on the PacketLED pins and a button. Nothing else:

```cpp
#include <PacketLED.h>
#include <SecurePairLed.h>
#include <transport/EspNowTransport.h>

ArduinoLedPhy phy(32, 33);              // LED anode (an ADC1 pin), cathode; ESP32-C3/C6: 0, 1
PacketLED led(phy);
PacketLedTransport optical(led);        // pairing, over the LED
EspNowTransport radio;                  // messages, over ESP-NOW
LedDisplay display(optical);            // code and status on the same LED
NvsPairStorage storage;                 // keys survive a reset
SecurePair pairing(optical, storage, display, display);
SecureLink channel(pairing, radio);     // encrypted messages
ButtonInput button(13);                 // button between GPIO13 and GND; ESP32-C3/C6: 3

void setup() {
  button.begin();
  led.begin();
  pairing.begin();
  pairing.provision(button);            // first start, or button held while starting: pairs
  radio.begin();                        // after the pairing: Wi-Fi would disturb the LEDs
  channel.sync();
}

void loop() {
  // Your code. For example, a short press sends "hello" to every paired board...
  if (button.read() == PairButton::Short) {
    PeerInfo peer;
    for (size_t i = 0; pairing.peerInfo(i, peer); ++i) channel.send(peer.id, "hello");
  }
  // ...and this receives:
  uint8_t buf[256];
  PeerId from;
  int n = channel.receive(buf, sizeof(buf), from);
  if (n > 0) {
    // n bytes from the board `from`, decrypted and checked
  }
}
```

That is all the pairing code an application needs:

- `provision()` pairs on the first start, and again whenever the button is held as the board starts: a new key for a known board, or a new board. Otherwise it returns at once.
- `loop()` has nothing to do for the pairing, and the button is all yours.
- `radio.begin()` comes after the pairing, because PacketLED times the light to the microsecond and Wi-Fi interrupts could disturb it.
- To pair while the application runs instead, call `handle()` in `loop()`. A long press within 10 s of `begin()` starts a pairing in the background, and `handle()` passes it the presses. To start one at any time, from a menu for instance, set `PairConfig::policy` to `Always` and call `requestPairing()`. See [API.md](API.md).

The complete reference is in [API.md](API.md). The LedPairEspNowLink example is this sketch, with a light show on the other board at each press.

### Other media

The same library, without LEDs: pairing over ESP-NOW, messages over LoRa. The code blinks on the board's own LED and can be printed too:

```cpp
#include <LoRa.h>
#include <SecureLink.h>
#include <SecurePair.h>
#include <storage/NvsPairStorage.h>
#include <transport/EspNowTransport.h>
#include <transport/LoRaTransport.h>
#include <ui/ButtonInput.h>
#include <ui/GpioLedSink.h>
#include <ui/LedDisplay.h>

using namespace securepair;

EspNowTransport radio;                  // pairing
LoRaTransport lora;                     // messages
GpioLedSink statusLed(LED_BUILTIN);     // or the pin of your LED
LedDisplay display(statusLed);          // code and status on the board's LED
NvsPairStorage storage;
SecurePair pairing(radio, storage, display, display);
SecureLink channel(pairing, lora);
ButtonInput button(13);

void setup() {
  button.begin();
  statusLed.begin();
  LoRa.begin(868E6);                    // your frequency and pins
  lora.begin();
  radio.begin();
  pairing.begin(PairConfig::forRadio());   // shorter pauses than with LEDs
  pairing.provision(button);
  channel.sync();
}

void loop() {
  // channel.send() and channel.receive(), as above
}
```

Over a radio there is no physical closeness to rely on. Anybody in range could try to sit in the middle, and comparing the code is what stops them. Show the code where the user can really compare it.

### Keys stored encrypted

`NvsPairStorage` keeps the pairing keys in clear until the chip has a key of its own, the chip key. In clear, whoever has the board in hand can read them over USB with esptool, and a copy of the flash works on another board. On chips with an HMAC peripheral (ESP32-S2, S3, C3, C5, C6, H2 and P4) the chip key prevents both:

1. Upload the **ChipKeySetup** example to each board, type `burn` and confirm. It writes a random 256-bit key into an eFuse key block (KEY5, unless it is taken). No program and no tool can read it back; only the chip's HMAC peripheral can use it. Writing eFuses cannot be undone.
2. Nothing else changes in the sketches. From the next start, `NvsPairStorage` seals every record with AES-256-GCM under a key derived from the chip key. The flash shows no pairing keys, and a copy does not open on another board. The examples say at startup when the keys are still in clear.

```cpp
NvsPairStorage storage;                         // encrypted once the chip has its key
NvsPairStorage storage(Encryption::Required);   // encrypted or nothing, for a product
```

With `Encryption::Required` a board without its key does not pair at all. Either way, a board whose encrypted records do not open (damaged, or copied from another chip) stops there, and never goes back to clear.

Write the chip key before the first pairing. A board paired earlier starts over. What it saved in clear is erased, not imported, because anyone able to write the flash could have planted it. NVS may keep old copies in the flash until it reuses the space; to wipe them for certain, erase the flash once, with *Tools > Erase All Flash Before Sketch Upload* set to *Enabled*, then back to *Disabled*.

It does not stop someone who can run their own code on the same chip, over USB or by flashing another program. That code can use the chip key too. Secure boot, set up with ESP-IDF, with the download mode and JTAG turned off, closes that door. Writing back an older copy of the flash is not detected either. On the original ESP32, which has no HMAC peripheral, use flash encryption with NVS encryption.

## Transports

A transport moves packets. `SecurePair` takes one for pairing, and each `SecureLink` takes one for messages: the same one by default, or another.

| Transport | Range | Message size | Notes |
|---|---|---|---|
| `PacketLedTransport` | a few cm to 2 m, line of sight (depends on the LEDs) | 35 bytes | one LED per board; pair them a few cm apart |
| `EspNowTransport` | tens of meters | 217 bytes | Wi-Fi channel shared by all boards |
| `LoRaTransport` | kilometers | 216 bytes | not tested on hardware yet; mind the duty cycle |

Any medium that carries packets of 58 bytes or more can be added, such as Bluetooth, a UART or another radio. [EXTENDING.md](EXTENDING.md) explains what a transport must do and where to start from, and the same for displays, input and storage. [ARCHITECTURE.md](docs/ARCHITECTURE.md) describes how the library is put together.

## Examples

| Example | Pairing | Messages | Hardware |
|---|---|---|---|
| **Provisioning** | LED | | the smallest: pairing only |
| **LedOnly** | LED | LED | one LED and a button per board |
| **LedPairEspNowLink** | LED | ESP-NOW | one LED and a button; a press makes the other LED play a light show |
| **LedPairLoRaLink** | LED | LoRa | plus an SX1276/78 module |
| **EspNowOnly** | ESP-NOW | ESP-NOW | a button |
| **EspNowPairLoRaLink** | ESP-NOW | LoRa | an SX1276/78 module and a button |
| **WaveshareC3Zero** | LED | LED | Waveshare ESP32-C3-Zero: code and status on its RGB LED |
| **ChipKeySetup** | | | writes the chip key, once per board; from then on the pairing keys are saved encrypted |
| **CryptoSelfTest** | | | checks the cryptography on the board |

## Tests

`extras/test` runs two boards as threads on a PC, over a simulated medium that loses frames and acknowledgements. It covers pairing, re-pairing, rejection, timeouts, tampered and replayed messages, storage failures, the recovery of an interrupted re-pairing, two re-pairings cut short in a row, the reboot of either board, delayed and replayed challenge answers, several media used side by side, the acknowledgement layer used by ESP-NOW and LoRa, oversized radio frames, presses during the code and the timing of the button, and the storage, in clear and encrypted: damaged, swapped, copied and lost records. The cryptography is checked against values computed with the Python `cryptography` package.

They need Python and the Zig C++ compiler, and take about two minutes. On Windows:

```bash
python -m pip install ziglang
powershell extras/test/run_tests.ps1
```

On Linux or macOS, run `pwsh extras/test/run_tests.ps1` if PowerShell is installed, or build the same files directly:

```bash
python -m ziglang c++ -std=c++17 -O2 -I src -I extras/test extras/test/test_securepair.cpp src/*.cpp src/internal/*.cpp src/storage/*.cpp -o securepair_test && ./securepair_test
```

## Troubleshooting

The examples print what happens on the Serial Monitor (115200 baud): look there first.

- **`Pairing: failed (no peer)`.** Start the pairing on both boards within about 20 s. With PacketLED, keep the LEDs face to face, a few centimeters apart, and shade them from sunlight or a strong lamp. With ESP-NOW, both boards must be on the same Wi-Fi channel.
- **The two codes differ.** Reject with a long press. Something in between changed the exchange, or another pair of boards is pairing nearby. Try again.
- **`Pairing: failed (protocol error)`.** Usually another pair of boards pairing nearby. Try again a little farther away from them.
- **Nothing on the Serial Monitor** with an ESP32-C3 or C6 on native USB. Enable *Tools > USB CDC On Boot*.
- **The sketch does not start while the button is held.** The button is on a boot strapping pin, such as BOOT. Move it to another pin.
- **`keys in clear (see the ChipKeySetup example)`.** Normal until the chip has its own key.
- **`Saved keys do not open`.** The flash was copied from another board, or is damaged. Erase it, with `NvsPairStorage::factoryReset()` or *Erase All Flash Before Sketch Upload*, and pair again.
- **Messages refused after a reboot.** Call `SecureLink::sync()` at startup, and `receive()` regularly on both boards: it also answers the other board's challenges.

## Limitations

- ESP32 only for now.
- Without a chip key the pairing keys are saved in clear. The original ESP32 has no HMAC peripheral, so it cannot have a chip key; there, enable NVS encryption and flash encryption.
- After a board reboots, the first message from each peer that did not reboot is refused and answered with a challenge; `SecureLink::sync()` does this at startup so that nothing is lost.
- On a broadcast medium like ESP-NOW or LoRa, any board in range acknowledges a frame: with more than two boards around, "delivered" means "received by someone".
- If a board is reset to factory settings, the other boards keep its old record until `forget()`.
- Pairing over the LEDs runs with the radio off, and then the ESP32's random generator is not a full-entropy source. The library mixes in LED and timing noise through SHA-256, but the quality of that noise has not been measured.

## Related work

Comparing a short code between two devices is not a new idea, and SecurePair builds on it:

- S. Vaudenay, *Secure Communications over Insecure Channels Based on Short Authenticated Strings*, CRYPTO 2005: why a short code is enough once each side has committed to its key.
- J. M. McCune, A. Perrig, M. K. Reiter, *Seeing-Is-Believing: Using Camera Phones for Human-Verifiable Authentication*, IEEE Symposium on Security and Privacy 2005: a visual channel to authenticate two devices.
- R. Prasad, N. Saxena, *Efficient Device Pairing Using "Human-Comparable" Synchronized Audiovisual Patterns*, ACNS 2008: two devices blinking the same pattern in step, compared by the user.

What SecurePair adds is the combination: the same LED carries the keys and blinks the code, each board keeps a permanent identity and several peers, and the messages can then travel over any medium.

## Contributing

SecurePair is meant to grow. Useful contributions:

- test reports, especially LoRa on real modules;
- a review of the protocol;
- transports for other media (RadioLib modules, Bluetooth, UART);
- code displays (OLED, e-paper) and ports to other microcontrollers.

Open an issue or a pull request.

## Help us

If you find this project useful and would like to support its development, consider making a donation. Any contribution is greatly appreciated!

**Bitcoin (BTC) Addresses:**
- **1LToggio**f3rNUTCemJZSsxd1qubTYoSde6
- **3LToggio**7Xx8qMsjCFfiarV4U2ZR9iU9ob

## License

The **SecurePair** library is licensed under the Apache License, Version 2.0. You are free to use, modify, and distribute the library in compliance with the license.

Copyright (C) 2026 Luca Soltoggio - https://www.lucasoltoggio.it/
