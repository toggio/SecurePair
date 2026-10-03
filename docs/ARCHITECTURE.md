# SecurePair architecture

How the library is organized. The protocol itself is in [PROTOCOL.md](PROTOCOL.md); writing new transports, displays or storage is covered in [EXTENDING.md](../EXTENDING.md).

## Main decisions

- N:N, with no roles. Every board has a persistent identity and keeps up to 8 peer records (configurable). Which board speaks first is settled on the medium, and the keys are derived symmetrically.
- One pairing call. A pairing either adds a new peer or re-pairs a known one, and the peer's identity tells which.
- Pairing is one blocking procedure. `provision()` runs it in `setup()`, on the first start or when the button is held as the board starts, so `loop()` needs nothing. To pair while the application runs, `handle()` starts it in a task that exists only for that attempt. Outside a pairing SecurePair runs no code of its own.
- The medium is an interface: PacketLED, ESP-NOW, LoRa or anything else that moves packets. Pairing and messages may use different media, for instance pairing over the LEDs or ESP-NOW nearby, then talking over the radio.
- People are an interface too. The code can blink on a plain LED or an RGB LED, or be printed. Status patterns go to a separate interface, so the two can live on different outputs. The button is an interface as well.

## Files

```
src/
├── SecurePair.h / .cpp        lifecycle: identity, boot epoch, peers, repair window, task, handle()
├── SecureLink.h / .cpp        encrypted messages
├── SecurePairLed.h            one include for PacketLED setups
├── PairTypes.h                PeerId, PairCode, states, results, PairInput
├── PairConfig.h               timing and policy
├── PairTransport.h            interface: moving packets
├── PairStorage.h              interface: identity, epoch, peer records
├── DeviceKey.h                interface: a secret used through HMAC
├── PairDisplay.h              interfaces: code, status patterns, LED
├── LedArbiter.h               who owns a shared LED
├── transport/
│   ├── PacketLedTransport.h   PacketLED (PacketLED itself is not modified)
│   ├── EspNowTransport.h      ESP-NOW broadcast with acknowledgements
│   └── LoRaTransport.h        LoRa (arduino-LoRa) with acknowledgements
├── storage/
│   ├── NvsPairStorage.*       ESP32 NVS: sealed once the chip has its key, in clear before
│   ├── HmacChipKey.h          the chip's eFuse key, used through the HMAC peripheral
│   └── MemoryPairStorage.h    RAM, for tests
├── ui/
│   ├── LedDisplay.*           code and patterns on one plain LED
│   ├── RgbLedDisplay.*        code and patterns on a WS2812 RGB LED
│   ├── SerialCodeDisplay.h    code as six digits on any Print
│   ├── PairingLog.h           what is happening, in words, on any Print
│   ├── GpioLedSink.h          a plain LED on any pin
│   ├── ButtonInput.h          a push button: short and long presses
│   └── UiTiming.h             waiting to the microsecond, for the code's blinks
└── internal/
    ├── PairEngine.*           the state machine of one attempt
    ├── Protocol.*             message format and key schedule, no I/O
    ├── PeerTable.*            peer records in RAM and the key replacement rules
    ├── Datagram.*             framing and acknowledgements for radios, no I/O
    ├── PressDecoder.h         short and long presses from a button's edges, no I/O
    ├── Crypto.*               SHA-256, HMAC, HKDF, random pool
    ├── Seal.*                 records sealed with AES-256-GCM, for storage
    ├── PlainNvsStorage.*      NvsPairStorage records in clear, with CRC-32
    ├── SealedNvsStorage.*     NvsPairStorage records sealed
    ├── NvsNames.h             record names shared by the two
    ├── CryptoMbed.cpp         X25519 and AES-GCM through Mbed TLS (ESP32)
    └── CryptoPortable.cpp     portable X25519 and AES-GCM, for the host tests only
```

The transports are header-only, so that a sketch pulls in PacketLED, the Wi-Fi library or the LoRa library only if it uses them.

## Components

| Class | Does | Knows nothing about |
|---|---|---|
| `SecurePair` | identity, boot epoch, peers, repair window, pairing task, events | pins, message formats |
| `PairEngine` | one pairing attempt from start to end: states, timeouts, messages, commit | pins, NVS, Mbed TLS |
| `SecureLink` | encrypted frames, nonces, replay protection, challenges | pairing |
| `Protocol` | message layout, transcript, HKDF, code | I/O |
| `PeerTable` | peer records in RAM, two-key saving, promotion, rollback | protocol |
| `PairTransport` | acknowledged packets, a common instant for the code | cryptography |
| `CodeDisplay` | shows the code | transport |
| `StatusDisplay` | plays one short status pattern | when and how often |
| `LedSink` | turns an LED on and off | patterns |
| `PairInput` | reads the user's presses | pairing |
| `PairStorage` | identity, epoch, peer slots, atomic writes | protocol |
| `NvsPairStorage` | picks the format, clear or sealed, and keeps the records in NVS | protocol |
| `DeviceKey` | a secret used only through HMAC | storage formats |

## Lifecycle

```
setup():
  begin()                          with peers: READY blink, the repair window opens (10 s)
  provision(button)
    ├─ held at start ──> pair() now: a new key, or a new board
    ├─ no peers ───────> blinks UNPAIRED, waits for a press, pairs; repeats until saved
    └─ otherwise ──────> returns at once

loop(): nothing for SecurePair.

Pairing while the application runs (optional), in loop():
  handle(press)
    ├─ a pairing is running ──> Short confirms, Long rejects; returns true
    ├─ Long within the window ─> task: pair() -> task ends; returns true
    └─ otherwise ──────────────> returns false (the application's turn)
```

- `provision()` blocks: without a peer, or when the user asked for a pairing, the application has nothing to do anyway. Otherwise it costs one look at the button.
- With `handle()`, the window is checked when the long press comes; a pairing that has started finishes even if the window closes meanwhile. The window is a policy (`PairConfig::policy`), not a protocol limit.
- The task runs one priority above the caller. PacketLED needs precise timing and yields while listening, so `loop()` keeps running between frames.
- While the task runs, the pairing transport is busy, and so is any transport registered with `pauseDuringPairing()`. A `SecureLink` on those returns `Busy`; one on another transport keeps working.

## One LED, three jobs

With PacketLED the same LED transmits, receives and shows the code. `LedArbiter` gives it to one owner at a time: the transport, a status pattern, or the code. A pattern that finds the LED taken is skipped, never waited for: the transport has priority. Inside a pairing, ownership follows the state; the arbiter only makes a mistake visible.

A single LED adds one problem: the other board is looking at it. A blink here is light for the receiver over there. So the phases that involve both boards are aligned:

- the code starts at the same instant on both;
- while waiting for confirmation, both boards split time into the same 2 s cycles: first the status blink, on both at once, then messages.

```
0          400 ms                                            2000 ms
|--status--|------------------- messages --------------------|
  blink      listen; a board with something to send starts
             at a random point in the first 600 ms
```

A send that runs over into the next status slot just skips that blink. Before handing the LED back to PacketLED a pattern leaves it dark for 100 ms, so the dark level stays clean.

With a separate status LED or an RGB LED there is no conflict, and the cycles are kept anyway: they cost little and keep the behavior the same everywhere.

## LED patterns

The grammar holds on a plain LED and on an RGB one:

- **short** (80 ms): information, waiting;
- **long at the end** (1 s): success;
- **flicker** (10 Hz): error, and nothing else.

| Pattern | Plain LED | RGB LED |
|---|---|---|
| UNPAIRED | 1 short every 3 s | blue |
| READY | one 250 ms blink at boot | green |
| ARMED | 2 short | blue |
| STARTING | 3 short, 1 s apart, then dark (face the LEDs) | blue |
| code | 20 slots of 500 ms: 120 ms = 0, 350 ms = 1 | the same timing, and one of four colors per blink |
| WAIT_CONFIRM | 2 short every 2 s | amber |
| WAIT_PEER_CONFIRM | 1 short every 2 s | amber |
| SAVED | 3 quick, then 1 long | green |
| ERROR | flicker 1 s, pause, flicker 1 s | red |

On the RGB LED the color of blink *i* comes from bits *i*+1 and *i*+2 of the same 20-bit code (blue, green, yellow, magenta; red is kept for errors). It adds no information that the blink lengths do not already carry, but a difference between two codes then shows up in several blinks at once, and the colors are easier to compare than lengths. Because the timing is the same, a board with an RGB LED can still be compared with one that blinks a plain LED.

## Storage (ESP32 NVS)

`NvsPairStorage` keeps its records in namespace `securepair`, in one of two formats. `begin()` picks the format: sealed if the chip has its key (`DeviceKey::available()`), in clear otherwise, or nothing at all with `Encryption::Required`. With the key, whatever is saved in clear is erased first, never imported: someone able to write the flash could have planted it. A sealed identity that does not open stops `begin()`; the format is never chosen by what happens to open.

| Key | Format | Contents |
|---|---|---|
| `id` | clear | identity key pair, CRC-32 |
| `epoch` | clear | boot counter |
| `p00` ... `p07` | clear | one peer record per slot, CRC-32 |
| `sid` | sealed | identity key pair and boot epoch |
| `s00` ... `s07` | sealed | one peer record per slot |

One record is one blob, written with one `nvs_set_blob` and `nvs_commit`: after a power cut NVS holds the old or the new value. There is no separate index to get out of step; the peers are found by reading the slots.

Writes: one per boot (the epoch), two per pairing, one per reboot of each peer (its epoch).

### In clear

If `epoch` is missing (a damaged entry) while peer records are there, the peers are erased before the epoch starts again from 1, in every slot: their keys never meet the same epoch twice. The identity stays, so the other boards recognize this one when it pairs again.

### Sealed

Every value is `version (1) | nonce (12) | ciphertext | tag (16)`, sealed with AES-256-GCM by `internal/Seal.cpp`:

- The key. In `begin()` the DeviceKey computes HMAC("SecurePair storage") once, and HKDF turns the result into an encryption key and a nonce key, which stay in RAM.
- The nonce is an HMAC of the context, the record and 16 random bytes, cut to 12 bytes. Two different records share a nonce only if two 96-bit HMAC outputs collide, which is negligible, even if the random source is weak.
- The context is authenticated but not stored. It holds the namespace, the record name and, for a peer, the public key of the identity, so a record moved to another slot, namespace or board does not open.
- Deleting records only makes the board forget. The epoch shares the identity's record, and the peers are bound to the identity. Without the identity the board starts over, and the old peer records no longer open, so no saved key is used again with an epoch that starts from 1. A damaged identity stops `begin()` instead.
- Rollback is not detected: an older copy of the whole flash, written back, looks valid.

## Concurrency

- The pairing task owns its transport from start to end.
- `confirm()`, `reject()` and `cancel()` set atomic flags: call them from `loop()`, another task or an interrupt. `ButtonInput` times presses in an interrupt, each from its own edges (`internal/PressDecoder.h`), so a long press read late is still long.
- The event callback runs in the pairing task. Keep it short, and do not use the pairing transport from it.
- The peer table is protected by a mutex, so a `SecureLink` on another transport may keep working during a re-pairing and sees the new key as soon as it is saved.
- Message counters and replay windows live in `SecurePair`, not in each `SecureLink`, and have their own mutex. Two links of the same pairing (say one over the LEDs, one over ESP-NOW) therefore never reuse a nonce, and a frame accepted over one medium is refused over the other.
- The random pool is protected by a mutex too.
