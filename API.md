# SecurePair API

Reference for SecurePair 0.5.0 (beta). See the [README](README.md) for an overview. Everything is in namespace `securepair`; `SecurePairLed.h` also brings it into scope with `using namespace securepair`.

## Setup

With PacketLED:

```cpp
#include <PacketLED.h>
#include <SecurePairLed.h>

ArduinoLedPhy phy(anodePin, cathodePin);
PacketLED led(phy);
PacketLedTransport optical(led);
LedDisplay display(optical);
NvsPairStorage storage;
SecurePair pairing(optical, storage, display, display);
SecureLink channel(pairing);
ButtonInput button(buttonPin);
```

`SecurePairLed.h` includes SecurePair, SecureLink, NVS storage, the PacketLED transport, the displays, `ButtonInput` and the Serial log. Without PacketLED, include what you use: `SecurePair.h`, `SecureLink.h`, `storage/NvsPairStorage.h`, `transport/EspNowTransport.h`, `transport/LoRaTransport.h`, `ui/LedDisplay.h`, `ui/GpioLedSink.h`, `ui/RgbLedDisplay.h`, `ui/SerialCodeDisplay.h`, `ui/ButtonInput.h`, `ui/PairingLog.h`.

## SecurePair

### `SecurePair(PairTransport &transport, PairStorage &storage, CodeDisplay &codeDisplay, StatusDisplay &statusDisplay)`

`transport` carries the pairing. `codeDisplay` shows the code, `statusDisplay` the status patterns; they may be the same object (`LedDisplay`, `RgbLedDisplay`).

### `bool begin(const PairConfig &config = PairConfig())`

Call it after the transport has been started. It:

- loads the identity of this board, or creates it on the first start;
- advances the boot counter in storage (the epoch, used for message nonces);
- loads the peers;
- if there are peers, plays READY and opens the repair window.

Returns `false` if the storage cannot be used. Messages cannot be sent until `begin()` has succeeded.

### `PairResult provision(PairInput &input)`

The one call an application needs, in `setup()`, after `begin()`:

- if `input` was held as the board started (`heldAtStart()`: the button pressed at power-on or reset), it pairs at once: a new key for a board already known, or a new board;
- then, as long as there is no peer, it blinks UNPAIRED every 3 s, waits for a Short press on `input` and pairs, until a peer has been saved.

With peers and no button held it returns `Ok` at once, otherwise the result of the last attempt: a failed re-pairing leaves the old keys in place, and the board goes on with them. If `begin()` did not succeed it returns `StorageError` at once, and no pairing can start.

```cpp
pairing.begin();
pairing.provision(button);
```

### `bool handle(PairButton press)`

Only to pair while the application runs, from `loop()`. A Long press within the repair window (the 10 s after `begin()`, or always with `PairConfig::policy` set to `Always`) starts a pairing in the background, and `handle()` passes it the answers. "Repair" is short for re-pairing here and in the names below. Pass it the user's press, or `PairButton::None`:

- while a pairing is running: Short confirms, Long rejects. Returns `true`; the pairing transport, and the LED if it is shared, must not be used meanwhile;
- within the repair window, if there are peers: Long starts a pairing (see `requestPairing()`). Returns `true`;
- otherwise returns `false` and does nothing: the press is the application's.

```cpp
void loop() {
  PairButton press = button.read();
  if (pairing.handle(press)) return;
  // your code; `press` is yours here
}
```

### `void pauseDuringPairing(PairTransport &transport)`

Calls `transport.pause()` when a pairing starts and `transport.resume()` when it ends. For a radio carrying the messages while the LEDs pair, when pairing while the application runs: Wi-Fi interrupts could disturb PacketLED's timing. With `provision()` in `setup()`, starting the radio after it is enough. Up to two transports.

### Peers

| Method | Returns |
|---|---|
| `bool hasPeer()` | at least one peer is saved |
| `size_t peerCount()` | number of peers |
| `bool peerInfo(size_t index, PeerInfo &out)` | the peer at `index` (0 to `peerCount() - 1`) |
| `const PeerId &localId()` | this board's identity |
| `uint32_t epoch()` | this boot's number |
| `bool forget(const PeerId &id)` | removes a peer |
| `bool forgetAll()` | removes all peers; the identity stays |

`PeerInfo` fields:

| Field | Meaning |
|---|---|
| `id` | the peer's identity |
| `proven` | `false` after a first pairing whose last message was lost: this board saved the peer, the peer may not have. It turns `true` at the first message from the peer; pairing again also fixes it |
| `keyChanging` | two keys are held while a re-pairing completes |
| `pairedEpoch` | the epoch of the pairing |

`PeerId` is 8 bytes (`id.b`), with `==` and `!=`.

### Lower-level calls

`handle()` and `provision()` are built on these:

| Method | Does |
|---|---|
| `PairResult pair(PairInput *input = nullptr)` | one complete pairing attempt, blocking (up to about a minute and a half if nobody confirms). Reads `input` for the answers; with `nullptr`, use `confirm()` and `reject()` |
| `bool requestPairing()` | runs `pair()` in a background task and returns at once. `false` if a pairing is running, or if there are peers and the window is closed. A new peer is added; a known one gets a new key |
| `void confirm()`, `void reject()`, `void cancel()` | the user's answers; callable from `loop()`, another task or an interrupt. `confirm()` counts only after the code has been shown; `reject()` during the code takes effect when it ends |
| `bool busy()` | a pairing is running |
| `bool repairWindowOpen()` | pairing again is still allowed (a comparison with `millis()`) |
| `void closeRepairWindow()` | closes it early |
| `PairResult lastResult()` | result of the last attempt |
| `void onEvent(PairEventFn fn)` | calls `fn(const PairEvent &)` on every state change |
| `static const char *resultText(PairResult r)`, `static const char *stateText(PairState s)` | short descriptions |

The pairing task runs one priority above the caller. The event function runs in that task when there is one: keep it short, and do not use the pairing transport from it.

`PairEvent` fields:

| Field | Meaning |
|---|---|
| `state` | `Armed`, `Starting`, `Rendezvous`, `Exchange`, `ShowCode`, `WaitConfirm`, `WaitPeerConfirm`, `Commit`, `Saved`, `Failed` |
| `result` | in `Saved` and `Failed` |
| `peer` | from `Exchange` on |
| `repair` | the peer was already known: a re-pairing |
| `code` | the code, from `ShowCode` on: `code.digits()` (six digits), `code.bitAt(i)` (20 bits) |

### `PairResult`

| Value | Meaning |
|---|---|
| `Ok` | saved |
| `NoPeer` | nobody answered |
| `Timeout` | the exchange or the confirmation took too long |
| `Rejected` | rejected here or on the other board |
| `Cancelled` | `cancel()`, or Long before the code |
| `ProtocolError` | a message failed its checks: tampering, or another pair of boards nearby |
| `StorageFull` | no free slot for a new peer (reported before the code) |
| `StorageError` | the storage could not be written, or `begin()` did not succeed |
| `CryptoError` | key generation failed |
| `Busy` | a pairing is already running |

## PairConfig

All times are in milliseconds. The defaults suit PacketLED; `PairConfig::forRadio()` returns shorter pauses for ESP-NOW and LoRa. Both boards must use the same values.

| Field | Default | Meaning |
|---|---|---|
| `policy` | `BootWindow` | `BootWindow`: pairing again only within `repairWindowMs` of `begin()`. `Always`: whenever the application asks |
| `repairWindowMs` | 10000 | how long after `begin()` `handle()` and `requestPairing()` may start a pairing |
| `alignPauseMs` | 3000 | after the press, time to put the LEDs face to face |
| `rendezvousMs` | 20000 | from the press: nobody answered, `NoPeer` |
| `exchangeMs` | 40000 | from the press, until the code |
| `confirmMs` | 30000 | from the end of the code |
| `maxPeers` | 8 | limited by the storage |
| `offerMinMs`, `offerMaxMs` | 300, 1500 | pause between two offers, random |
| `resendMs` | 2500 | repeat a message if the peer is silent |
| `codeLeadMs` | 3000 | pause before the code |
| `codeMs` | 10000 | how long the code is shown, whatever the display |
| `cycleMs`, `uiSlotMs` | 2000, 400 | while waiting for confirmation: cycle length, and the part of it for the status blink |
| `sendJitterMs` | 600 | random delay of a send within a cycle |
| `commitMs` | 6000 | after saving, how long to wait for the other board's last message |
| `pollMs` | 30 | receive granularity |

## SecureLink

### `SecureLink(SecurePair &pairing)`, `SecureLink(SecurePair &pairing, PairTransport &transport)`

Encrypted messages to the saved peers, over the pairing transport or another one. Several `SecureLink` objects of the same pairing, one per medium, can be used side by side: they share the message counters and the replay protection, so a frame accepted over one medium is refused if it comes again over another.

### `SendResult send(const PeerId &to, const uint8_t *data, size_t len, bool reliable = true)`, `SendResult send(const PeerId &to, const char *text)`

Encrypts and sends. With `reliable` it waits for the transport's acknowledgement.

| `SendResult` | Meaning |
|---|---|
| `Ok` | sent (and acknowledged, if reliable) |
| `NotDelivered` | not acknowledged; it may still have arrived |
| `UnknownPeer` | no such peer |
| `BadLength` | empty, or longer than `maxPayload()` |
| `Busy` | a pairing is using or has paused this transport |
| `NotReady` | `SecurePair::begin()` did not succeed |
| `Exhausted` | 4 billion messages to one peer since boot: restart |
| `CryptoError` | the encryption failed; nothing was sent |

### `int receive(uint8_t *buf, size_t cap, PeerId &from, uint32_t timeoutMs = 0)`

Waits up to `timeoutMs` for a message (0: check once) and returns its size, or 0. `from` tells who sent it. Call it regularly: it also answers the challenges of peers that rebooted.

A message is delivered at most once. After this board reboots, the first message from each peer that did not reboot is refused and answered with a challenge; the peer's answer lets the next messages through. `sync()` does this in advance.

### Other methods

| Method | Does |
|---|---|
| `size_t maxPayload()` | largest message: 35 bytes over PacketLED, 217 over ESP-NOW, 216 over LoRa |
| `size_t sync()` | challenges every peer now, so that no message is refused after a reboot. Returns the number of challenges delivered; the answers are handled by `receive()` |
| `bool synced(const PeerId &peer)` | that peer's messages are accepted without a challenge |
| `void requireFreshness(bool on)` | `false` for one-way links: the first message after a reboot is accepted without a challenge. After a reboot of this board, each message the peer sent since its own last reboot can then be replayed once |
| `const Stats &stats()` | counters, below |
| `static const char *resultText(SendResult r)` | a short description |

`Stats`: `sent`, `received`, `foreign` (not SecureLink frames), `unknownKey`, `replayed`, `badAuth` (tampered, reflected or wrong key), `tooLong` (did not fit `cap`), `refused` (waiting for a challenge answer), `proofs` (challenges answered), `keyUpdates` (re-pairings completed by messages), `notSaved` (not delivered: the storage could not save the peer's new epoch).

## Transports

### `PacketLedTransport(PacketLED &led)`

Over an existing `PacketLED` object, which must have been started with `begin()`. It is also the `LedSink` of the PacketLED LED, for `LedDisplay`.

### `EspNowTransport(uint8_t channel = 1)`

| Member | Does |
|---|---|
| `bool begin()` | starts Wi-Fi in station mode and ESP-NOW |
| `void end()` | stops them |
| `bool running()` | |
| `attempts`, `ackTimeoutMs` | tries of a reliable send (3), wait for each acknowledgement (30 ms) |

All boards must be on the same Wi-Fi channel. Frames are broadcast and acknowledged by the adapter.

### `LoRaTransport(LoRaClass &radio = LoRa)`

Needs the LoRa library by Sandeep Mistry. Not tested on hardware yet.

| Member | Does |
|---|---|
| `bool begin()` | call after `LoRa.begin(frequency)`; enables the LoRa CRC |
| `attempts`, `ackTimeoutMs` | tries of a reliable send (3), wait for each acknowledgement (400 ms; raise it at higher spreading factors) |

Set up pins, frequency and spreading factor with the LoRa library, the same on every board.

## Displays and input

### `LedDisplay(LedSink &led, const LedTiming &timing = LedTiming())`

Code and status patterns on a plain LED: the PacketLED one (pass the `PacketLedTransport`) or any other (`GpioLedSink`). Both `CodeDisplay` and `StatusDisplay`.

### `RgbLedDisplay(uint8_t pin, uint8_t brightness = 40, rgb_led_color_order_t order = LED_COLOR_ORDER_GRB)`

Code and status patterns on a WS2812 RGB LED. Both `CodeDisplay` and `StatusDisplay`. The code keeps the short/long timing of `LedDisplay`, and each blink also has one of four colors taken from the same code. The Waveshare ESP32-C3-Zero has the LED on GPIO10 with `LED_COLOR_ORDER_RGB`.

- `set(Rgb c)`, `off()`: use the LED from the application between pairings.
- `info`, `ask`, `good`, `bad`, `codeColors[4]`: the colors, changeable.

### `SerialCodeDisplay(Print &out)`

Prints the code as six digits and as its short/long pattern. A `CodeDisplay` only.

### `GpioLedSink(uint8_t pin, bool activeLow = false)`

An LED on a pin, for `LedDisplay`. `LED_BUILTIN` works, including boards where it is an RGB LED. Call `begin()` in `setup()`.

### `NullStatusDisplay`

A `StatusDisplay` that does nothing.

### `ButtonInput(uint8_t pin, bool activeLow = true, uint16_t longMs = 1000)`

A push button, by default between the pin and GND with the internal pull-up. Presses are timed in an interrupt from their own edges, so none is lost, and none changes kind, while a pairing keeps the CPU busy. Call `begin()` in `setup()`.

`PairButton read()` returns `Short` when a press shorter than `longMs` ends, `Long` as soon as the button has been held for `longMs` (or when it ends, if `read()` was not called meanwhile), and `None` otherwise. Each press is returned once. A `Long` wins over a `Short` not read yet, even while it is still held: that `Short` waits until the press going on ends, so a rejection right after a confirmation is not lost.

`void clear()` forgets the presses not read yet; a press still going on can then end only as `Long`. The pairing calls it when the code ends, so a press made during the code never confirms.

`bool heldAtStart()` returns `true` if the button was already pressed when `begin()` ran, that is at power-on or reset; `provision()` takes it as a request to pair. That press never counts as Short or Long. Do not use a boot strapping pin, such as the BOOT button (GPIO9 on the C3 and C6, GPIO0 on the ESP32): held during a reset, it starts the ROM download mode instead of the sketch.

### Serial log

In `ui/PairingLog.h`: what is happening, in plain words, on any `Print`. The examples use it.

- `logPairingStatus(Print &out, SecurePair &pairing, bool keysEncrypted)`: after `begin()`, this board's identity, whether its keys are encrypted and the boards it is paired with; or why `begin()` failed.
- `logPairingEvent(Print &out, const PairEvent &e)`: one line per step of a pairing, the code included. Call it from the function given to `onEvent()`.
- `logPeerId(Print &out, const PeerId &id)`: an identity as 16 hex digits.

## Storage

### `NvsPairStorage(Encryption mode = Encryption::IfAvailable, const char *ns = "securepair", size_t slots = 8)`

In the ESP32 NVS, namespace `ns`, up to 16 slots. If the chip has its own key (`HmacChipKey`, written by the ChipKeySetup example), every record is sealed with AES-256-GCM under a key derived from it: the flash holds no key in clear, and a record opens only on the same chip, in the same slot and namespace. Without the key the records are saved in clear, or, with `Encryption::Required`, `begin()` fails and no pairing can start.

- `bool encrypted()`: after `begin()`, whether the records are sealed.
- `begin()` also fails when the chip has its key but the saved identity does not open (damaged, or written by another chip): SecurePair then refuses to pair, rather than fall back to clear or start over with a new identity.
- Once the chip has its key, the records saved in clear are erased, never imported: a board paired before the key was written starts over.
- `factoryReset()` erases identity, epoch and peers, in clear and sealed, even when `begin()` fails: the board becomes a new device to the others.

`NvsPairStorage(DeviceKey &key, Encryption mode = Encryption::IfAvailable, const char *ns = "securepair", size_t slots = 8)` does the same with another key, a secure element for instance ([EXTENDING.md](EXTENDING.md)).

### `HmacChipKey`

The chip's own key, used by `NvsPairStorage`, on chips with an HMAC peripheral (ESP32-S2, S3, C3, C5, C6, H2, P4): 256 bits in an eFuse block with purpose HMAC_UP, read-protected, written once by the ChipKeySetup example. The class uses it through the HMAC peripheral and never writes eFuses. `available()` tells whether the chip has a usable key, `block()` which block holds it (0 to 5 for KEY0 to KEY5, or -1).

### `MemoryPairStorage`

In RAM, for tests. Nothing survives a reset: every start needs a new pairing.

## Writing your own

[EXTENDING.md](EXTENDING.md) describes the contracts of `PairTransport`, `CodeDisplay`, `StatusDisplay`, `LedSink`, `PairInput`, `PairStorage` and `DeviceKey`.
