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
 * PairTransport over LoRa, with Sandeep Mistry's arduino-LoRa library
 * (SX1276/77/78/79 modules such as the RFM95 and the TTGO LoRa32).
 * Not tested on hardware yet: reports and fixes are welcome.
 *
 * Frames are broadcast and acknowledged by this adapter (internal/Datagram.h).
 * LoRa has no addresses, so every frame carries the sender's ESP32 MAC address.
 * SecureLink picks the recipient by key; frames for other boards fail
 * authentication there.
 *
 * Set up the radio yourself (pins, frequency, spreading factor), the same on
 * every board, then call begin():
 *
 *   LoRa.setPins(18, 14, 26);
 *   LoRa.begin(868E6);
 *   lora.begin();
 *
 * Mind the local rules on air time: in Europe, 1% duty cycle on most of the
 * 868 MHz band. At SF7 a full frame takes about 0.4 s.
 *
 * Header-only, so that sketches not using it do not need arduino-LoRa.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>
#include <LoRa.h>
#include <esp_mac.h>
#include <esp_random.h>
#include <string.h>

#include "../PairTransport.h"
#include "../internal/Datagram.h"

namespace securepair {

class LoRaTransport : public PairTransport {
 public:
  static constexpr size_t kMaxFrame = 255;
  static constexpr size_t kMaxPayload = kMaxFrame - dgram::kHeaderLen - dgram::kAddrLen;   // 245

  explicit LoRaTransport(LoRaClass &radio = LoRa) : radio_(radio) {}

  /** Call after LoRa.begin(). Enables the LoRa CRC. */
  bool begin() {
    if (esp_read_mac(addr_, ESP_MAC_WIFI_STA) != ESP_OK) return false;
    seq_ = (uint16_t)esp_random();   // a rebooted board must not repeat its last number
    radio_.enableCrc();
    return true;
  }

  size_t maxPayload() const override { return kMaxPayload; }

  bool send(const uint8_t *data, size_t len, bool reliable, SyncMark *mark) override {
    if (len == 0 || len > kMaxPayload) return false;
    uint8_t frame[kMaxFrame];
    const uint16_t seq = ++seq_;
    const size_t n = dgram::buildDataFrom(frame, seq, addr_, data, len);
    const uint8_t tries = reliable ? attempts : 1;
    for (uint8_t a = 1; a <= tries; ++a) {
      transmit(frame, n);
      if (!reliable) {
        if (mark) *mark = SyncMark{::micros(), false};
        return true;
      }
      waitSeq_ = seq;
      acked_ = false;
      const uint32_t start = ::millis();
      while (!acked_ && ::millis() - start < ackTimeoutMs) poll();
      if (acked_) {
        if (mark) *mark = SyncMark{ackAtUs_, a == 1};
        return true;
      }
      delay(10 + esp_random() % 50);   // two boards may have collided: desynchronize
    }
    if (mark) *mark = SyncMark{::micros(), false};
    return false;
  }

  int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) override {
    const uint32_t start = ::millis();
    do {
      if (count_ > 0) {
        const Item &it = queue_[head_];
        const size_t n = it.len < cap ? it.len : cap;
        memcpy(buf, it.data, n);
        if (mark) *mark = SyncMark{it.atUs, true};
        head_ = (head_ + 1) % kQueueLen;
        --count_;
        return (int)n;
      }
      poll();
    } while (::millis() - start < timeoutMs);
    return 0;
  }

  uint32_t micros() override { return ::micros(); }
  uint32_t millis() override { return ::millis(); }
  void delayMs(uint32_t ms) override { delay(ms); }

  uint8_t attempts = 3;          // reliable sends
  uint16_t ackTimeoutMs = 400;   // per attempt; raise it at higher spreading factors

 private:
  static constexpr int kQueueLen = 2;

  struct Item {
    uint32_t atUs;
    uint8_t len;
    uint8_t data[kMaxPayload];
  };

  void transmit(const uint8_t *frame, size_t len) {
    radio_.beginPacket();
    radio_.write(frame, len);
    radio_.endPacket();   // blocks until sent
  }

  // Reads at most one frame: an ACK for us, or data to queue and acknowledge.
  void poll() {
    const int size = radio_.parsePacket();
    if (size <= 0) return;
    uint8_t in[kMaxFrame];
    size_t n = 0;
    while (radio_.available() && n < sizeof(in)) in[n++] = (uint8_t)radio_.read();
    dgram::Frame f;
    if (!dgram::parse(in, n, kMaxPayload, f)) return;
    if (f.kind == dgram::kAck) {
      if (f.seq == waitSeq_ && memcmp(f.dest, addr_, dgram::kAddrLen) == 0) {
        ackAtUs_ = ::micros();
        acked_ = true;
      }
      return;
    }
    if (f.kind != dgram::kDataFrom) return;
    Item *fresh = nullptr;
    if (!dedup_.duplicate(f.src, f.seq)) {
      if (count_ == kQueueLen) return;   // full: no ACK, the sender retries
      fresh = &queue_[(head_ + count_) % kQueueLen];
      fresh->len = (uint8_t)f.len;
      memcpy(fresh->data, f.payload, f.len);
      ++count_;
      dedup_.remember(f.src, f.seq);
    }
    // Retries are acknowledged again: the first ACK may have been lost.
    uint8_t ack[dgram::kAckLen];
    dgram::buildAck(ack, f.seq, f.src);
    transmit(ack, sizeof(ack));
    if (fresh) fresh->atUs = ::micros();   // the end of the ACK: the sender's instant too
  }

  LoRaClass &radio_;
  uint8_t addr_[dgram::kAddrLen] = {};
  uint16_t seq_ = 0;
  uint16_t waitSeq_ = 0;
  bool acked_ = false;
  uint32_t ackAtUs_ = 0;
  dgram::Dedup dedup_;
  Item queue_[kQueueLen];
  int head_ = 0, count_ = 0;
};

}  // namespace securepair

#endif
