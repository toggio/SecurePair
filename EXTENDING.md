# Extending SecurePair

SecurePair talks to the outside world through seven small interfaces. The library ships implementations for the common cases; this page explains the contract of each one, so you can write your own: another radio, a display, a different button, another kind of storage or of key.

| Interface | Moves or shows | Included |
|---|---|---|
| `PairTransport` | packets | `PacketLedTransport`, `EspNowTransport`, `LoRaTransport` |
| `CodeDisplay` | the code | `LedDisplay`, `RgbLedDisplay`, `SerialCodeDisplay` |
| `StatusDisplay` | status patterns | `LedDisplay`, `RgbLedDisplay`, `NullStatusDisplay` |
| `LedSink` | one LED, on or off | `PacketLedTransport`, `GpioLedSink` |
| `PairInput` | the user's presses | `ButtonInput` |
| `PairStorage` | identity, epoch, peers | `NvsPairStorage`, `MemoryPairStorage` |
| `DeviceKey` | a secret for the encrypted storage | `HmacChipKey` |

All of them are in namespace `securepair`; the snippets below assume `using namespace securepair;`. The host tests in `extras/test` contain two more: an in-memory transport and a display that only records the code.

## PairTransport

```cpp
class PairTransport {
 public:
  virtual size_t maxPayload() const = 0;
  virtual bool send(const uint8_t *data, size_t len, bool reliable, SyncMark *mark) = 0;
  virtual int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) = 0;
  virtual uint32_t micros() = 0;
  virtual uint32_t millis() = 0;
  virtual void delayMs(uint32_t ms) = 0;
  virtual void pause() {}                              // optional
  virtual void resume() {}                             // optional
  virtual size_t entropy(uint8_t *buf, size_t cap);    // optional
};
```

**The quickest start** is to copy `transport/LoRaTransport.h`. It is a complete transport for a medium that has neither addresses nor acknowledgements, which is the common case. Replace the radio calls (`beginPacket()`, `write()`, `endPacket()`, `parsePacket()`, `read()`) with those of your medium, and keep the rest.

**`maxPayload()`**: at least 58 bytes, the longest pairing message. SecureLink gets this minus 29 bytes. If the medium carries less, split and join inside the adapter.

**`send(reliable = true)`** blocks until the other side has acknowledged the packet and returns `true`, or gives up after a few retries and returns `false`. If the medium has no acknowledgements, the adapter adds them: `internal/Datagram.h` has the framing, and `EspNowTransport` and `LoRaTransport` use it. A retransmitted packet must be delivered **once**: retries carry the same sequence number, and the receiver drops the copies but still acknowledges them, since the first acknowledgement may have been lost.

**`send(reliable = false)`** sends once and returns without waiting. It is used for the pairing offers, which are repeated anyway.

**`receive()`** waits up to `timeoutMs` for a packet and returns its size, or 0. With a timeout of 0 it only checks. Packets come from anybody in range and are not authenticated yet: check each length against your buffers before copying, and drop what does not fit. ESP-NOW v2, for one, delivers frames up to 1470 bytes; `dgram::parse()` takes the limit.

**`SyncMark`** is the one subtle part. Both boards must show the code at the same instant, and they agree on it through the end of an exchange:

- after a reliable `send()`: `atUs` = the `micros()` when the acknowledgement arrived; `exact` = `true` only if the **first** attempt was acknowledged;
- after `receive()`: `atUs` = the `micros()` when the acknowledgement was sent; `exact` = `true`.

A few milliseconds of difference between the two boards are fine: on a blinking LED nobody sees them.

**`pause()` and `resume()`**, optional: stop and restart the medium. `SecurePair::pauseDuringPairing()` calls them around a pairing on another medium. `resume()` should restart the medium only if it was running before `pause()`.

**`entropy()`**, optional: physical noise for the random pool, such as a few ADC readings. `PacketLedTransport` returns short dark readings of the LED.

**Timing.** The default `PairConfig` suits PacketLED, where a frame takes tenths of a second. On a fast medium, `PairConfig::forRadio()` gives shorter pauses. On a slow one, such as LoRa at a high spreading factor, raise `resendMs` and the adapter's acknowledgement timeout.

**Security.** The transport needs no security of its own: everything that matters is authenticated by SecurePair. But mind the range. Over a medium that reaches far, comparing the code is the only protection against a man in the middle, and the user must really compare it.

## CodeDisplay

```cpp
class CodeDisplay {
 public:
  virtual void show(const PairCode &code, uint32_t startUs, uint32_t durationMs) = 0;
};
```

Show `code` starting exactly at `startUs` (a `micros()` value, the same instant on both boards) within `durationMs` (10 s by default). Returning early is fine, as a printed number does: the pairing waits for the full duration anyway, so both boards leave the code together.

`PairCode` gives you the code in the forms a person can compare:

- `code.bitAt(i)`, i = 0..19: the 20 bits, for blinking (short = 0, long = 1);
- `code.digits()`: 0..999999, for a display.

If the code will be compared with a board that blinks a plain LED, keep the timing of `LedDisplay`: 20 slots, the LED on for 24% of a slot for 0 and 70% for 1. Two numbers, or two blinking LEDs, can be compared; a number with a blinking LED cannot.

A display for an SSD1306 OLED:

```cpp
class OledCodeDisplay : public CodeDisplay {
 public:
  explicit OledCodeDisplay(Adafruit_SSD1306 &d) : d_(d) {}
  void show(const PairCode &code, uint32_t startUs, uint32_t) override {
    while ((int32_t)(startUs - micros()) > 0) delay(1);
    d_.clearDisplay();
    d_.setTextSize(3);
    d_.setCursor(0, 20);
    d_.printf("%03u %03u", (unsigned)(code.digits() / 1000), (unsigned)(code.digits() % 1000));
    d_.display();
  }
 private:
  Adafruit_SSD1306 &d_;
};
```

`SerialCodeDisplay` takes any `Print`, so a display driver that is a `Print` works with it directly.

## StatusDisplay

```cpp
class StatusDisplay {
 public:
  virtual void play(StatusPattern pattern) = 0;
};
```

Play **one short burst** of the pattern and return. The pairing decides when to call it and how often; that is how the repeating patterns stay aligned on the two boards.

- A burst for `WaitConfirm` or `WaitPeerConfirm` must fit in `uiSlotMs` (400 ms).
- `Starting` may take up to `alignPauseMs` (3 s): it is the moment to face the LEDs.
- If the output is shared with a transport (a single LED), check its `LedArbiter` and skip the pattern when the transport owns it; leave the LED dark for a moment before returning.

`NullStatusDisplay` does nothing, for boards without any status output.

## LedSink

```cpp
class LedSink {
 public:
  virtual void set(bool on) = 0;
  virtual LedArbiter *arbiter() { return nullptr; }
};
```

What `LedDisplay` blinks. `GpioLedSink(pin, activeLow)` covers an LED on a pin. Return an arbiter only if the LED is also used by a transport, as `PacketLedTransport` does.

## PairInput

```cpp
class PairInput {
 public:
  virtual PairButton read() = 0;
  virtual bool heldAtStart() { return false; }
  virtual void clear() {}
};
```

Return `PairButton::Short` or `PairButton::Long` once for each press, and `PairButton::None` otherwise. It must not block. `provision()` and `pair()` call it often during a pairing; to pair while the application runs, you call it in `loop()` and pass the result to `handle()`. If presses can wait somewhere until `read()`, as in an interrupt or a serial buffer, time them where they happen: a long press read late is still `Long`.

`clear()` drops the presses not read yet. The pairing calls it when the code ends, so that only a press made after the whole code was shown confirms. A press still going on may end as `Long`, never as `Short`.

`heldAtStart()` is the user's way to ask for a pairing as the board starts: `ButtonInput` returns `true` when the button was already held at power-on. `provision()` then pairs at once, even when the board has peers.

A touch pad, a rotary encoder or a command on the Serial Monitor work as well as a button:

```cpp
class SerialInput : public PairInput {
 public:
  PairButton read() override {
    if (!Serial.available()) return PairButton::None;
    const char c = Serial.read();
    return c == 'y' ? PairButton::Short : c == 'n' ? PairButton::Long : PairButton::None;
  }
  void clear() override {
    while (Serial.available()) Serial.read();   // typed during the code: does not count
  }
};
```

## PairStorage

```cpp
class PairStorage {
 public:
  virtual bool begin() = 0;
  virtual bool loadIdentity(IdentityRecord &out) = 0;
  virtual bool saveIdentity(const IdentityRecord &id) = 0;
  virtual bool nextEpoch(uint32_t &epoch) = 0;
  virtual size_t capacity() const = 0;
  virtual bool loadPeer(size_t slot, PeerRecord &out) = 0;
  virtual bool savePeer(size_t slot, const PeerRecord &rec) = 0;
  virtual bool erasePeer(size_t slot) = 0;
};
```

Three rules matter for security:

1. **`savePeer()` is atomic.** After a power cut the slot holds either the old record or the new one, never a mix. Write the whole record in one operation, or write it to a second place and switch over.
2. **The epoch never goes back while a key is saved.** The epoch keeps nonces unique across reboots. `nextEpoch()` has saved the new value before it returns, and if the saved epoch is lost, the peers must go with it: `NvsPairStorage` erases them before it starts the epoch again. A saved key used with an epoch that starts over would repeat nonces.
3. **`loadPeer()` returns `false` for a damaged record** (check a CRC), rather than garbage.

`capacity()` is the number of peer slots. A record takes about 130 bytes, the identity 64.

## DeviceKey

```cpp
class DeviceKey {
 public:
  virtual bool available() = 0;
  virtual bool derive(const void *message, size_t len, uint8_t out[32]) = 0;
};
```

`NvsPairStorage storage(myKey)` uses it in place of the chip's own key. In `begin()` it asks `available()` whether the secret is there: if so the records are sealed, otherwise they are saved in clear (or `begin()` fails, with `Encryption::Required`). Then it calls `derive()` once and takes its key from the result. Return 32 bytes that depend on `message` and on a secret the program cannot read, the same every time, and `false` if the secret is missing. `HmacChipKey` computes an HMAC-SHA256 with the chip's HMAC peripheral; a secure element on I2C, such as an ATECC608, could do the same.

## Testing

`extras/test/test_securepair.cpp` runs two boards as threads on a PC, over a simulated medium that loses frames and acknowledgements. A new transport is easiest to test the same way: keep its framing and acknowledgement rules in plain code without I/O, as `internal/Datagram.cpp` does, test that on the PC, and leave only thin hardware calls in the adapter.
