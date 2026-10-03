# Changelog

## 0.5.0 (beta)

First public release.

- Pairing of ESP32 boards, two or more: X25519 key exchange with a
  commitment, and a 20-bit code the user compares on the two boards. Each
  board keeps up to 8 peers (16 if configured). Pairing again with a known
  board replaces its key, and the old key stays until both boards have saved
  the new one.
- Pairing over PacketLED (one LED per board), ESP-NOW or LoRa. LoRa has not
  been tested on hardware yet. Other media can be added as transports.
- SecureLink: encrypted, authenticated messages (AES-256-GCM) over the
  pairing medium or another one, protected against replays even after a
  reboot.
- NvsPairStorage: the keys are saved in NVS, encrypted with a key held in
  the chip's eFuses on chips that have one (ESP32-S2, S3, C3, C5, C6, H2,
  P4; see the ChipKeySetup example).
- The code is shown on the PacketLED LED, a plain LED, an RGB LED or the
  Serial Monitor. One button is enough: the pairing runs in setup(), and
  runs again when the button is held as the board starts.
- Pairing protocol version 5 (docs/PROTOCOL.md): a board pairs only with
  boards that run the same version.
- Nine examples, and host tests that run two boards on a PC.
