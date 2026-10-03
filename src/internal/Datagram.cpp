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
 * Acknowledged datagrams.
 */

#include "Datagram.h"

#include <string.h>

namespace securepair {
namespace dgram {

namespace {

void header(uint8_t *out, uint8_t kind, uint16_t seq) {
  out[0] = kMagic;
  out[1] = kind;
  out[2] = (uint8_t)(seq >> 8);
  out[3] = (uint8_t)seq;
}

}  // namespace

size_t buildData(uint8_t *out, uint16_t seq, const uint8_t *payload, size_t len) {
  header(out, kData, seq);
  memcpy(out + kHeaderLen, payload, len);
  return kHeaderLen + len;
}

size_t buildDataFrom(uint8_t *out, uint16_t seq, const uint8_t src[kAddrLen], const uint8_t *payload,
                     size_t len) {
  header(out, kDataFrom, seq);
  memcpy(out + kHeaderLen, src, kAddrLen);
  memcpy(out + kHeaderLen + kAddrLen, payload, len);
  return kHeaderLen + kAddrLen + len;
}

size_t buildAck(uint8_t *out, uint16_t seq, const uint8_t dest[kAddrLen]) {
  header(out, kAck, seq);
  memcpy(out + kHeaderLen, dest, kAddrLen);
  return kAckLen;
}

bool parse(const uint8_t *in, size_t len, size_t maxPayload, Frame &out) {
  if (len < kHeaderLen || in[0] != kMagic) return false;
  out.kind = in[1];
  out.seq = (uint16_t)(in[2] << 8 | in[3]);
  out.payload = in + kHeaderLen;
  out.len = len - kHeaderLen;
  out.src = nullptr;
  out.dest = nullptr;
  if (out.kind == kDataFrom) {
    if (len <= kHeaderLen + kAddrLen) return false;
    out.src = in + kHeaderLen;
    out.payload = in + kHeaderLen + kAddrLen;
    out.len = len - kHeaderLen - kAddrLen;
    return out.len <= maxPayload;
  }
  if (out.kind == kAck) {
    if (len != kAckLen) return false;
    out.dest = in + kHeaderLen;
    out.len = 0;
    return true;
  }
  return out.kind == kData && out.len > 0 && out.len <= maxPayload;
}

bool Dedup::duplicate(const uint8_t src[kAddrLen], uint16_t seq) const {
  for (int i = 0; i < kSenders; ++i)
    if (used_[i] && memcmp(src_[i], src, kAddrLen) == 0) return seq_[i] == seq;
  return false;
}

void Dedup::remember(const uint8_t src[kAddrLen], uint16_t seq) {
  for (int i = 0; i < kSenders; ++i) {
    if (used_[i] && memcmp(src_[i], src, kAddrLen) == 0) {
      seq_[i] = seq;
      return;
    }
  }
  // New sender: entries are reused in turn, the oldest first.
  const int i = next_;
  next_ = (next_ + 1) % kSenders;
  memcpy(src_[i], src, kAddrLen);
  seq_[i] = seq;
  used_[i] = true;
}

}  // namespace dgram
}  // namespace securepair
