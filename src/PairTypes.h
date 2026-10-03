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
 * Common types and protocol constants (docs/PROTOCOL.md).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace securepair {

constexpr uint8_t kProtocolVersion = 5;
constexpr uint8_t kSuite = 0x01;           // X25519 / SHA-256 / AES-256-GCM
constexpr size_t kKeyLen = 32;
constexpr size_t kPeerIdLen = 8;
constexpr size_t kKeyIdLen = 4;
constexpr size_t kXidLen = 8;
constexpr size_t kMaxPairMessage = 58;     // fits the 64-byte PacketLED payload
constexpr uint8_t kCodeBits = 20;

/** Stable device identifier: SHA-256("SecurePair/id" || identity public key)[0..7]. */
struct PeerId {
  uint8_t b[kPeerIdLen];
  bool operator==(const PeerId &o) const { return memcmp(b, o.b, kPeerIdLen) == 0; }
  bool operator!=(const PeerId &o) const { return !(*this == o); }
};

/**
 * The code the user compares (the SAS, short authentication string): the same
 * on both boards unless somebody is in the middle.
 */
struct PairCode {
  uint32_t value;                          // kCodeBits significant bits, MSB first
  bool bitAt(uint8_t i) const { return (value >> (kCodeBits - 1 - i)) & 1; }
  uint32_t digits() const { return value % 1000000; }   // for numeric displays
};

/** Outcome of a pairing attempt. */
enum class PairResult : uint8_t {
  Ok,
  NoPeer,          // nobody answered during the rendezvous
  Timeout,         // exchange or confirmation took too long
  Rejected,        // reject() here or ABORT from the peer
  Cancelled,       // cancel()
  ProtocolError,   // bad commitment, MAC, sequence or zero shared secret
  StorageFull,     // new peer and no free slot (detected before the code)
  StorageError,
  CryptoError,
  Busy,            // a pairing is already running
};

/**
 * Status patterns played by a StatusDisplay. While the boards talk nothing is
 * played; the code itself goes to the CodeDisplay.
 */
enum class StatusPattern : uint8_t {
  Unpaired,
  Ready,
  Armed,
  Starting,
  WaitConfirm,
  WaitPeerConfirm,
  Saved,
  Error,
};

/** States of one pairing attempt, reported through PairEvent (docs/PROTOCOL.md). */
enum class PairState : uint8_t {
  Armed,
  Starting,
  Rendezvous,
  Exchange,
  ShowCode,
  WaitConfirm,
  WaitPeerConfirm,
  Commit,
  Saved,
  Failed,
};

/** A press as seen by SecurePair. The application decides what a press is. */
enum class PairButton : uint8_t { None, Short, Long };

/** Where a blocking pairing reads the user's answers (ButtonInput is one). */
class PairInput {
 public:
  virtual ~PairInput() {}
  /** Returns a press once, then None until the next one. Must not block. */
  virtual PairButton read() = 0;
  /**
   * Whether the user asked for a pairing as the board started: for
   * ButtonInput, the button was already held then. provision() then pairs.
   */
  virtual bool heldAtStart() { return false; }
  /**
   * Forgets the presses not read yet. A press still going on may end as Long,
   * never as Short. Called when the code ends: a confirmation must come
   * after the user has seen the whole code.
   */
  virtual void clear() {}
};

struct PairEvent {
  PairState state;
  PairResult result;     // meaningful in Saved / Failed
  PeerId peer;           // valid from Exchange on (after IDENT)
  bool repair;           // true if the peer was already known
  PairCode code;         // valid from ShowCode on
};

typedef void (*PairEventFn)(const PairEvent &);

}  // namespace securepair
