/*
 * SecurePair v. 0.5.0 - 03/10/2026
 *
 * Cryptographically secure pairing and communication between ESP32 boards:
 * pair through a single standard LED with the LX.25 protocol, or over
 * ESP-NOW and LoRa.
 *
 * Copyright (C) 2026 under Apache License, Version 2.0
 *
 * @author Luca Soltoggio
 * https://www.lucasoltoggio.it
 * https://github.com/toggio/SecurePair
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * Acknowledged datagrams over a broadcast medium, for EspNowTransport and
 * LoRaTransport. Pure logic, no I/O: testable on the PC.
 *
 *   data:        | magic | 'D' | seq (2) | payload ... |
 *   data + from: | magic | 'S' | seq (2) | source address (6) | payload ... |
 *   ack:         | magic | 'A' | seq (2) | destination address (6) |
 *
 * Frames are broadcast, so no peer list is needed. An ACK names the station
 * it is meant for; retries keep their sequence number and are acknowledged
 * again but delivered once. ESP-NOW tells who sent a frame, so it uses 'D';
 * media without addresses (LoRa) carry the source in the frame with 'S'.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace securepair {
namespace dgram {

constexpr uint8_t kMagic = 0xB5;
constexpr uint8_t kData = 'D';
constexpr uint8_t kDataFrom = 'S';
constexpr uint8_t kAck = 'A';
constexpr size_t kHeaderLen = 4;
constexpr size_t kAddrLen = 6;
constexpr size_t kAckLen = kHeaderLen + kAddrLen;

size_t buildData(uint8_t *out, uint16_t seq, const uint8_t *payload, size_t len);
size_t buildDataFrom(uint8_t *out, uint16_t seq, const uint8_t src[kAddrLen], const uint8_t *payload,
                     size_t len);
size_t buildAck(uint8_t *out, uint16_t seq, const uint8_t dest[kAddrLen]);

struct Frame {
  uint8_t kind;
  uint16_t seq;
  const uint8_t *payload;   // data
  size_t len;
  const uint8_t *src;       // data + from
  const uint8_t *dest;      // ack
};

/**
 * Checks a received frame. Data with a payload longer than `maxPayload` (the
 * receiver's buffer) is refused: a sender may use frames longer than ours.
 */
bool parse(const uint8_t *in, size_t len, size_t maxPayload, Frame &out);

/** Remembers the last sequence number of a few senders. */
class Dedup {
 public:
  /** true if (src, seq) is the last frame delivered from src. */
  bool duplicate(const uint8_t src[kAddrLen], uint16_t seq) const;
  /** Records a delivered frame. */
  void remember(const uint8_t src[kAddrLen], uint16_t seq);

 private:
  static constexpr int kSenders = 8;
  uint8_t src_[kSenders][kAddrLen] = {};
  uint16_t seq_[kSenders] = {};
  bool used_[kSenders] = {};
  int next_ = 0;
};

}  // namespace dgram
}  // namespace securepair
