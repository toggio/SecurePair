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
 * PairTransport over ESP-NOW.
 *
 * Frames are broadcast and acknowledged by this adapter (internal/Datagram.h),
 * so there are no MAC addresses to manage: SecureLink picks the recipient by
 * key, and anything not meant for a board fails authentication there.
 * ESP-NOW encryption is not used; SecurePair does not need it.
 *
 * ESP-NOW reaches tens of meters: pairing over it has no physical proximity,
 * and comparing the code is the only protection against a man in the middle.
 *
 * One EspNowTransport per sketch: ESP-NOW callbacks carry no context.
 * Header-only, so that sketches not using it do not pull in the Wi-Fi library.
 */

#pragma once

#ifdef ARDUINO

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <string.h>

#include "../PairTransport.h"
#include "../internal/Datagram.h"

namespace securepair {

class EspNowTransport : public PairTransport {
 public:
  static constexpr size_t kMaxPayload = ESP_NOW_MAX_DATA_LEN - dgram::kHeaderLen;   // 246

  /** All boards must use the same Wi-Fi channel (the router's one if they are connected). */
  explicit EspNowTransport(uint8_t channel = 1) : channel_(channel) {}

  /** Starts Wi-Fi in station mode and ESP-NOW. */
  bool begin() {
    if (running_) return true;
    if (!queue_) queue_ = xQueueCreate(kQueueLen, sizeof(Item));
    if (!queue_) return false;
    WiFi.mode(WIFI_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);   // no modem sleep: frames must be heard at any time
    esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
    if (esp_now_init() != ESP_OK) return false;
    esp_now_peer_info_t peer = {};
    memset(peer.peer_addr, 0xFF, 6);
    peer.channel = 0;   // current channel
    peer.ifidx = WIFI_IF_STA;
    if (!esp_now_is_peer_exist(peer.peer_addr) && esp_now_add_peer(&peer) != ESP_OK) {
      esp_now_deinit();
      return false;
    }
    esp_wifi_get_mac(WIFI_IF_STA, mac_);
    seq_ = (uint16_t)esp_random();   // a rebooted board must not repeat its last number
    self_ = this;
    xQueueReset(queue_);
    running_ = true;
    esp_now_register_recv_cb(onReceive);
    return true;
  }

  /** Stops ESP-NOW and turns Wi-Fi off, including any connection the sketch made. */
  void end() {
    if (!running_) return;
    running_ = false;
    esp_now_unregister_recv_cb();
    esp_now_deinit();
    WiFi.mode(WIFI_OFF);
  }

  bool running() const { return running_; }

  // Used by SecurePair::pauseDuringPairing(): off during a pairing, back on after
  // if it was running.
  void pause() override {
    resumeAfter_ = running_;
    end();
  }
  void resume() override {
    if (resumeAfter_) begin();
    resumeAfter_ = false;
  }

  size_t maxPayload() const override { return kMaxPayload; }

  bool send(const uint8_t *data, size_t len, bool reliable, SyncMark *mark) override {
    if (!running_ || len == 0 || len > kMaxPayload) return false;
    uint8_t frame[ESP_NOW_MAX_DATA_LEN];
    const uint16_t seq = ++seq_;
    const size_t n = dgram::buildData(frame, seq, data, len);
    static const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t tries = reliable ? attempts : 1;
    for (uint8_t a = 1; a <= tries; ++a) {
      acked_ = false;
      waitSeq_ = seq;
      const bool queued = esp_now_send(broadcast, frame, n) == ESP_OK;
      if (!reliable) {
        if (mark) *mark = SyncMark{::micros(), false};
        return queued;
      }
      const uint32_t start = ::millis();
      while (!acked_ && ::millis() - start < ackTimeoutMs) delay(1);
      if (acked_) {
        if (mark) *mark = SyncMark{ackAtUs_, a == 1};
        return true;
      }
      delay(2 + esp_random() % 10);   // two boards may have collided: desynchronize
    }
    if (mark) *mark = SyncMark{::micros(), false};
    return false;
  }

  int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) override {
    if (!running_) {
      if (timeoutMs) delay(timeoutMs);
      return 0;
    }
    Item it;
    if (xQueueReceive(queue_, &it, pdMS_TO_TICKS(timeoutMs)) != pdTRUE) return 0;
    if (mark) *mark = SyncMark{it.atUs, true};
    const size_t n = it.len < cap ? it.len : cap;
    memcpy(buf, it.data, n);
    return (int)n;
  }

  uint32_t micros() override { return ::micros(); }
  uint32_t millis() override { return ::millis(); }
  void delayMs(uint32_t ms) override { delay(ms); }

  uint8_t attempts = 3;         // reliable sends
  uint16_t ackTimeoutMs = 30;   // per attempt

 private:
  static constexpr int kQueueLen = 6;

  struct Item {
    uint32_t atUs;
    uint8_t len;
    uint8_t data[kMaxPayload];
  };

  // Runs in the Wi-Fi task: short work only.
  static void onReceive(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    EspNowTransport *t = self_;
    if (t && t->running_ && len > 0) t->handle(info->src_addr, data, (size_t)len);
  }

  void handle(const uint8_t *src, const uint8_t *data, size_t len) {
    // Anybody in range can send, and ESP-NOW v2 frames can be longer than ours:
    // parse() refuses data that would not fit Item::data.
    dgram::Frame f;
    if (!dgram::parse(data, len, kMaxPayload, f)) return;
    if (f.kind == dgram::kAck) {
      if (f.seq == waitSeq_ && memcmp(f.dest, mac_, 6) == 0) {
        ackAtUs_ = ::micros();
        acked_ = true;
      }
      return;
    }
    if (f.kind != dgram::kData) return;
    if (!dedup_.duplicate(src, f.seq)) {
      Item it;
      it.atUs = ::micros();
      it.len = (uint8_t)f.len;
      memcpy(it.data, f.payload, f.len);
      if (xQueueSend(queue_, &it, 0) != pdTRUE) return;   // full: no ACK, the sender retries
      dedup_.remember(src, f.seq);
    }
    // Retries are acknowledged again: the first ACK may have been lost.
    uint8_t ack[dgram::kAckLen];
    dgram::buildAck(ack, f.seq, src);
    static const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    esp_now_send(broadcast, ack, sizeof(ack));
  }

  static inline EspNowTransport *self_ = nullptr;   // ESP-NOW callbacks carry no context

  uint8_t channel_;
  volatile bool running_ = false;
  bool resumeAfter_ = false;
  QueueHandle_t queue_ = nullptr;
  uint8_t mac_[6] = {};
  uint16_t seq_ = 0;
  volatile uint16_t waitSeq_ = 0;
  volatile bool acked_ = false;
  volatile uint32_t ackAtUs_ = 0;
  dgram::Dedup dedup_;
};

}  // namespace securepair

#endif
