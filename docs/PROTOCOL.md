# SecurePair protocol

Protocol version 5. This document describes what goes over the medium and why, in
enough detail to write a compatible implementation. [ARCHITECTURE.md](ARCHITECTURE.md)
covers how the library is organized.

Every pairing message fits in 58 bytes, so the protocol runs over PacketLED (64-byte
payload) as well as over ESP-NOW or any other packet link.

## 1. Threat model

Two boards and a user who presses a button on each and looks at them. The attacker
controls the medium: it can read, drop, delay, inject and replay packets, and it can
sit in the middle, with its own LED and photodiode between the two boards or with a
radio in range.

The one channel the attacker does not control is the user's eyes, comparing the two
short authentication strings (SAS). The whole authentication of a pairing rests on
those 20 bits.

Goals:

- a man in the middle succeeds with probability 2⁻²⁰ per attempt, and every attempt is
  a pairing the user sees;
- no roles: both boards run the same code;
- a stable identity per board, so re-pairing is recognized without asking;
- a new key never replaces the current one until both users have confirmed, and the
  two boards converge even if power or the medium fail halfway.

Out of scope: a user who confirms without looking, and an attacker who reads the flash
of a board, which is left to the storage (see [Security notes](#12-security-notes)).

## 2. Primitives

| Use | Primitive | On ESP32 |
|---|---|---|
| Key agreement | X25519 | Mbed TLS |
| Hash, commitment, transcript | SHA-256 | portable code |
| MAC | HMAC-SHA256, truncated where noted | portable code |
| Key derivation | HKDF-SHA256 (RFC 5869) | portable code |
| Encryption | AES-256-GCM | Mbed TLS, hardware AES |

Suite `0x01` stands for this set; it is part of the transcript, so a downgrade would
show. MACs are compared in constant time, and an all-zero X25519 result (a low-order
point) aborts the pairing.

## 3. Identity

On its first start a board creates a persistent X25519 **identity key**
(`id_priv`, `id_pub`).

```
peerId = SHA-256("SecurePair/id" || id_pub)[0..7]      // 8 bytes
```

The `peerId` is only an index: it finds the record of a peer and tells a re-pairing
from a new peer. The identity itself is `id_pub`, stored in the peer record. Nobody
can pair under someone else's `peerId`, because the static Diffie-Hellman `ss` goes
into the key (section 6). A factory reset creates a new identity: to the other boards
it is a new peer, and the old record stays until `forget()`.

## 4. Pairing messages

All messages start with the same 10-byte header:

```
| ver 0x05 | type | xid (8) |
```

`xid` is the exchange ID, chosen by the board that offers. Messages with another
version, or with an `xid` other than the current one, are ignored.

| Message | Type | After the header | Bytes | Authenticated |
|---|---|---|---|---|
| OFFER | 0x01 | commitment C (32) | 42 | through the transcript |
| REVEAL | 0x02 | e_pub (32), nonce n (16) | 58 | through the transcript and the SAS |
| IDENT | 0x03 | GCM(id_pub) (32), tag (16) | 58 | yes, k_hs |
| SAS_SYNC | 0x04 | MAC (8) | 18 | yes, k_cf |
| CONFIRM | 0x05 | sender's keyId (4), MAC (16) | 30 | yes, k_cf |
| DONE | 0x06 | sender's keyId (4), MAC (16) | 30 | yes, k_cf |
| ABORT | 0x07 | reason (1) [, MAC (16) once keys exist] | 11 or 27 | after IDENT |

## 5. Flow

The medium may be half-duplex, so one board has to speak first. That board is called
the offerer (O), the other the responder (R). These are turn-taking roles only: the
keys are derived symmetrically (section 6).

```
     O                                                   R
     |  button, ARMED, STARTING                          |  button, ARMED, STARTING
     |  OFFER   xid, C = H(e_pub_O, n_O)  ------------->|  R has seen only C
     |<------------------  REVEAL  e_pub_R, n_R          |  R reveals before seeing e_pub_O
     |  REVEAL  e_pub_O, n_O  ------------------------->|  R checks C
     |                  ee, th1, SAS                     |
     |<------------------  IDENT   GCM(id_pub_R)         |
     |  IDENT   GCM(id_pub_O)  ------------------------>|  end of this exchange = t0
     |                  ss, th2, link key                |
     |  [SAS_SYNC only if IDENT needed retries]          |
     |---------- pause, then SAS for 10 s ---------------|
     |---------- WAIT_CONFIRM ---------------------------|
     |  CONFIRM, DONE, DONE (section 8)                  |
```

Over PacketLED at 1024 bit/s the exchange takes about 3.5 s.

### 5.1 Who offers

After STARTING each board picks a random `xid` and listens. Every 300-1500 ms
(random, `offerMinMs` to `offerMaxMs`) it sends an OFFER without waiting for an
acknowledgement, so it is listening again at once. A board that receives an OFFER
with a **higher** `xid` than its own becomes the responder and answers with REVEAL;
lower ones are ignored. A board that receives a REVEAL for its own `xid` is the
offerer.

The rule depends only on the two `xid` values, so both boards reach the same result
whatever order the packets arrive in, and nothing can deadlock: the board with the
higher `xid` keeps offering until the other one hears it.

Each acknowledged message is sent again if the answer does not come within
`resendMs`, or if the peer repeats its previous message (a sign that it missed the
answer). All messages are idempotent.

### 5.2 Why the commitment

With a 20-bit SAS, a man in the middle who sees one board's values before choosing
its own can simply try values until the SAS it shares with the first board equals the
one it shares with the second. That takes about 2²⁰ tries, and a try does not even
need a new key: another nonce changes the SAS too, for the price of a few hashes. A PC
gets there well within the time a pairing lasts. A short SAS is only safe if nobody
can choose their value after seeing the other's. With OFFER and REVEAL:

- O commits to its values (C) before seeing anything from R;
- R reveals its values before seeing O's;
- a man in the middle has to fix its values on both sides before it can know the
  outcome, so it succeeds with probability 2⁻²⁰.

Bluetooth numeric comparison rests on the same idea.

```
C = SHA-256("SecurePair/commit" || xid || e_pub_O || n_O)
```

## 6. Key schedule

`lo` is the side with the smaller `e_pub` (byte comparison), `hi` the other.
Everything that depends on direction uses lo and hi, never O and R.

```
ee      = X25519(e_priv_self, e_pub_peer)          // abort if all zero
th1     = SHA-256("SecurePair/5" || suite || xid || C
                  || e_pub_lo || n_lo || e_pub_hi || n_hi)
prk1    = HKDF-Extract(salt = th1, ikm = ee)
k_hs_lo = HKDF-Expand(prk1, "hs lo", 32)           // k_hs_hi likewise
SAS     = first 20 bits of HKDF-Expand(prk1, "sas", 4)

// after IDENT
ss      = X25519(id_priv_self, id_pub_peer)        // abort if all zero
th2     = SHA-256(th1 || id_pub_lo || id_pub_hi)
prk2    = HKDF-Extract(salt = th2, ikm = ee || ss)
linkKey = HKDF-Expand(prk2, "link", 32)            // the only key that is stored
keyId   = HKDF-Expand(prk2, "kid", 4)
k_cf_lo = HKDF-Expand(prk2, "cf lo", 32)           // k_cf_hi likewise
```

**The SAS comes from prk1, not prk2.** The identities travel after the commitment. If
the SAS also depended on `id_pub`, a man in the middle could search for an identity
key that makes the two SAS equal, and the commitment would be worthless. The
identities are still authenticated:

- if the SAS match, `ee` is shared with the real peer only;
- IDENT is encrypted and authenticated with keys derived from `ee`, so nobody can
  swap the identity inside it;
- CONFIRM and DONE use `k_cf`, which depends on `ss`, so each side proves it holds its
  own `id_priv`. This also prevents unknown-key-share: presenting someone else's
  `id_pub` as one's own.

IDENT is AES-256-GCM with the sender's `k_hs`, a nonce of 12 zero bytes (each key
encrypts one message only) and the header as associated data. As a side effect,
`id_pub` is hidden from passive listeners.

## 7. SAS and synchronization

The SAS window lasts `codeMs` (10 s) on both boards, whatever the display. On an LED
it is 20 slots of 500 ms: bit 0 lights the LED for 120 ms, bit 1 for 350 ms. An RGB LED
keeps that timing and gives blink *i* one of four colors from bits *i*+1 and *i*+2:
still 20 bits, shown twice over. A numeric display shows `SAS mod 10⁶` as six digits
(19.9 bits).

Both boards start the SAS at the same instant, `t0 + codeLeadMs` (3 s):

- **t0** is the end of the last acknowledged exchange, the offerer's final IDENT. The
  sender takes it when its send returns with the acknowledgement; the receiver when it
  has sent the acknowledgement.
- **Retransmissions.** Only the sender knows whether it had to retransmit: a repeated
  copy is acknowledged by the transport but not delivered again. If its IDENT needed
  retries, the offerer sends SAS_SYNC until one goes through at the first attempt (up
  to 4 tries). The responder listens during the pause, and every SAS_SYNC moves its t0.
- In the normal case there is no SAS_SYNC, and the pause simply gives the user time to
  look at the boards.

With a man in the middle the two boards show two unrelated codes. On LEDs blinking
side by side, about 10 of the 20 slots differ: nobody has to count.

## 8. Confirmation and commit

### 8.1 The problem

Over a medium that loses messages, no protocol can guarantee that both boards save
the new key or neither does (the two generals problem): whoever sends the last message
cannot know it arrived. SecurePair therefore aims at **convergence**:

1. a board saves only after it has authenticated proof that the other user confirmed
   too;
2. it saves before announcing it (write-ahead);
3. it sends with the new key only once it knows the other board has saved it;
4. until it has proof that the peer sends with the new key, it still accepts the old
   one when receiving;
5. any later authenticated message (DONE, or a SecureLink frame) moves the state
   forward;
6. each board tells the other which key it sends with, so that a new pairing first
   settles whatever an earlier one left pending (8.5).

### 8.2 Messages and rules

- `CONFIRM = kid || HMAC(k_cf_sender, "confirm" || header || th2 || kid)[0..15]`: my
  user confirmed.
- `DONE = kid || HMAC(k_cf_sender, "done" || header || th2 || kid)[0..15]`: my user
  confirmed, I have your confirmation, and **I have saved**. A DONE implies a CONFIRM.

`kid` is the `keyId` of the key the sender sends to the receiver with at the moment it
sends the message, or four zero bytes if the sender has no record of the receiver (8.5).
A DONE sent after a promotion therefore names the new key.

```
user confirms:
    peer's CONFIRM or DONE already here -> save (8.3), send DONE
        (if the peer is a key behind: only after its DONE, 8.5)
    otherwise                           -> send CONFIRM, WAIT_PEER_CONFIRM
peer's CONFIRM arrives:
    already confirmed here -> save, send DONE
    otherwise              -> remember it (the display does not change)
peer's DONE arrives:
    confirmed, not saved yet -> save knowing the peer saved, send DONE
    already saved            -> promote (8.3); if we now send with the new key,
                                send DONE again, naming it
    naming the new key       -> once our own DONE is acknowledged: drop the old key, done
user rejects, or timeout (only before saving):
    send ABORT (authenticated), discard the candidate
```

Once a board has saved, the peer may have saved too: from then on it neither rejects
nor aborts, and only the peer's messages move it.

A typical sequence, with A confirming first:

```
A: confirm -> CONFIRM_A ---------------------> B (remembers)
                                               B: confirm -> save (pending) -> DONE_B (old key)
A <------------------------------------------- DONE_B
A: save (knows B saved) -> DONE_A (new key) --> B: promote -> DONE_B (new key), drop the old key
A <------------------------------------------- DONE_B
A: drop the old key
```

If both confirm at once, the two CONFIRMs cross: each board saves and sends DONE,
promotes on the other's DONE, and sends DONE again naming the new key.

A press during the SAS does not confirm: the user did not watch all of it. When the SAS
ends, the input is cleared (`PairInput::clear()`), and a press still going on can then
end only as a rejection. A long press during the SAS rejects as soon as the SAS ends.
`ButtonInput` times each press from its own edges, so a long press is never taken for a
short one because the board was busy. An ABORT from the peer after this board saved
without knowing whether the peer had saved undoes the save: the peer only aborts before
saving.

### 8.3 What is saved

A peer record holds a **current** key (used to send and receive) and possibly an
**alternate** key (receive only), each with its `keyId`.

| When saving | Current (send) | Alternate (receive) | Flag |
|---|---|---|---|
| Re-pairing, peer not known to have saved | old | new | `kAltIsNew` |
| Re-pairing, peer known to have saved (its DONE arrived) | new | old | `kHasAlt` |
| First pairing, or the peer has none of our keys (8.5) | new | - | `kUnproven` until the peer's DONE |
| Stable | new | - | - |

Each later step is a single atomic write of the record:

- `kAltIsNew`, and the peer's DONE or a valid frame under the new key arrives: the new
  key becomes current. A frame under the old key changes nothing: it may have been sent
  before the pairing;
- a valid frame from the peer under the current key: the old alternate key is dropped,
  and `kUnproven` is cleared;
- a board drops the old key at the end of the pairing only when the peer's authenticated
  DONE names the new key: the peer sends with it. An acknowledgement of its own DONE is
  not enough, since on a broadcast radio it may come from another board, and the peer
  may take the DONE and then fail to save the change. Without that DONE the old key
  stays, for receiving only, until the peer's first frame under the new one.

### 8.4 Failures

| Failure | A | B | Result |
|---|---|---|---|
| Only A confirms, B times out | nothing saved | nothing saved | old association (or none) on both |
| B saves (pending) and loses power before DONE_B | times out, nothing saved | after reboot, new key in receive only | unchanged: both send with the old key |
| DONE_B lost | times out, nothing saved | pending, sends with the old key | unchanged; B's new key stays unused |
| A saves knowing B saved, DONE_A lost | sends new, accepts old | pending: sends old, accepts new | A's first frame promotes B; B's next frame lets A drop the old key |
| The same, then another re-pairing before any message | | | settled before saving (8.5): both send with the key of the first one |
| Power lost during a write | | | NVS keeps either the old or the new record; the record also has a CRC, or a GCM tag when sealed |

The one case that does not heal by itself is a **first** pairing where one board saved
and the other did not: the first one holds a record the other does not know.
`PeerInfo::proven` shows it, and pairing again replaces it (same `peerId`).

### 8.5 What the other board sends with

A record holds two keys at most, so a new pairing must not start from a state an
earlier one left pending. Say a re-pairing lost its last DONE: A sends with the new key
K1 and still accepts the old K0, B sends with K0 and accepts K1 as pending. A second
re-pairing, cut short before any message, would make each board keep the key it sends
with plus the new K2, and drop the one the other sends with.

The `kid` in CONFIRM and DONE prevents that. When a board saves, it compares the
peer's `kid` with its own record:

| Peer's `kid` | Meaning | Before saving |
|---|---|---|
| our current key | nothing pending | nothing |
| our pending new key (`kAltIsNew`) | the peer has saved it and uses it | promote it, as a frame under it would |
| our previous key (alternate, not new) | the peer has not seen our current key yet | save only after the peer's DONE: the peer has then saved, and moved to our current key, which it learns from our CONFIRM |
| none of our keys, or zeros | the peer has lost its records, e.g. its epoch (11.2) | drop the old record, `rxEpoch` included: the new key starts as in a first pairing |

In the example, B promotes K1 on seeing A's `kid`, and A saves only after B's DONE, when
B no longer needs K0. If the DONEs are lost, A saves nothing and reports a timeout: the
two boards go on with K1, and B holds K2 as pending. A transport acknowledgement of A's
CONFIRM would not do instead of B's DONE: on a broadcast radio it may come from another
board, and B may fail to save after taking the CONFIRM. The `keyId` is not secret: every
SecureLink frame carries it in clear. If a real `keyId` happened to be four zero bytes
(one chance in 2³²), the peer would start its record over, and the new key would still
work.

## 9. States and timeouts

A pairing attempt runs from the button press to SAVED or FAILED; outside of it no
pairing state exists.

```
ARMED -> STARTING -> RENDEZVOUS -> EXCHANGE -> SAS -> WAIT_CONFIRM -> WAIT_PEER_CONFIRM
                                                          |                  |
                                                          +---> COMMIT <-----+
                                                                   |
                                                                 SAVED
Before saving, any state -> FAILED on timeout, reject(), cancel(), ABORT or a protocol error.
```

| State | Ends with | Timeout (PairConfig) |
|---|---|---|
| ARMED, STARTING | end of the pattern, then `alignPauseMs` (3 s) to face the LEDs | - |
| RENDEZVOUS | OFFER / REVEAL | `rendezvousMs`, 20 s from the press |
| EXCHANGE | both IDENTs, t0 | `exchangeMs`, 40 s from the press |
| SAS | `codeLeadMs` + `codeMs` | - |
| WAIT_CONFIRM, WAIT_PEER_CONFIRM | confirm, reject, CONFIRM / DONE | `confirmMs`, 30 s from the end of the SAS |
| COMMIT | the peer's DONE | `commitMs`, 6 s, then SAVED anyway (8.3) |

While waiting for confirmation, time is split into cycles of `cycleMs` (2 s) that start
at the end of the SAS, the same instant on both boards. The first `uiSlotMs` (400 ms)
of each cycle is for the status pattern, the rest for messages. With a single LED this
keeps a board from blinking while the other one listens through its LED.

## 10. First pairing, new peer, re-pairing

The protocol is the same. The difference is in the storage, and a board knows which
case it is only after IDENT:

| Case | Recognized by | Saved in |
|---|---|---|
| First pairing | no records | a free slot |
| New peer | unknown `peerId` | a free slot. If there is none, `StorageFull` is reported **before** the SAS |
| Re-pairing | known `peerId` | the same slot, with the two keys of 8.3 |

`PairEvent::repair` tells the application which case it was.

## 11. SecureLink frames

### 11.1 Keys

A record holds one `linkKey`. Each direction gets its own key:

```
k(X->Y) = HKDF-Expand(linkKey, "dir " || hex(peerId_X) || hex(peerId_Y), 32)
```

A single key for both directions would mean two counters starting from 0 under the
same key (the same nonce for two messages: GCM loses both confidentiality and
integrity) and a frame reflected back to its sender being accepted.

### 11.2 Frame and nonce

```
| type (1) | keyId (4) | epoch (4) | counter (4) | ciphertext (n) | tag (16) |
```

29 bytes of overhead: 35 bytes of data over PacketLED, 217 over ESP-NOW, 216 over
LoRa. Epoch and counter are big-endian; the 13-byte header is the associated data.
The `keyId` selects the peer and the key (current or alternate) without revealing
the `peerId`.

| Type | Meaning | Payload |
|---|---|---|
| 0x21 | data | the application's bytes |
| 0x22 | challenge | 8 random bytes |
| 0x23 | proof | the 8 bytes of the challenge |

```
nonce = epoch (4) || counter (4) || 0x00000000
```

- **epoch**: the sender's boot counter, incremented and saved in NVS at every start,
  before anything is sent. If it cannot be saved, nothing is sent: reusing a GCM
  nonce is not recoverable, a failure is.
- **counter**: per peer, from 0 at every boot, and shared by all the media the board
  talks to that peer over. A counter is used up even if the send fails. After 2³²
  frames to the same peer in one boot, sending fails until a reboot.

Counters are never written to flash.

### 11.3 Replay protection

For each peer the receiver keeps, in RAM, the highest (epoch, counter) accepted and
a 64-frame window below it, which tolerates reordering. It is one window per peer,
whatever the medium a frame comes through: a frame accepted over ESP-NOW is refused
if it comes again over LoRa. In NVS it keeps `rxEpoch`, the highest epoch accepted,
written only when it grows: once per reboot of the peer. It is written before the frame
that raised it is delivered; if the write fails, the frame is not delivered
(`Stats::notSaved`), since after a reboot nothing could refuse it again. Undoing a save
(8.2) keeps the higher `rxEpoch`.

| Frame epoch | Verdict |
|---|---|
| below `rxEpoch` | old: refused |
| above `rxEpoch` | the peer rebooted after anything we accepted: new |
| equal, window already started in this boot | window check |
| equal, first frame since our own reboot | **cannot be judged**: see below |

After the receiver reboots it no longer remembers the counters of a peer that did not
reboot. A replayed frame from that peer's current boot would look new. So the
receiver:

1. refuses the frame (even an authentic one: it may be a replay) and sends a
   **challenge** with 8 fresh random bytes;
2. the peer answers with a **proof** frame carrying those bytes. The proof is
   necessarily new, and so is its counter;
3. the receiver starts its window at the proof's counter, marking everything below it
   as seen. From there messages flow.

If frames of the same epoch were accepted while the proof was on its way (a frame from a
newer epoch needs no challenge, see the table), the proof only adds its counter: the
window never moves back, so a proof held back by an attacker cannot make an earlier
frame new again.

The refused message is not delivered later: delivery is at most once. `sync()`
challenges every peer in advance, typically at startup, so that no message is refused.
The peer must be calling `receive()` to answer. For one-way links, where the peer cannot
answer, `requireFreshness(false)` accepts the first frame instead. After a receiver
reboot, each message the peer sent since its own last reboot can then be replayed once.

If `rxEpoch` goes down, because a new pairing started the record over (8.5), what the
receiver remembers of that peer in RAM starts over too, as after a reboot.

The window check happens before decryption, but the state changes only when the tag
is valid: a forged frame cannot move the window.

## 12. Security notes

| Issue | Handling |
|---|---|
| Short SAS and a man in the middle | commitment (5.2): 2⁻²⁰ per attempt |
| Confirmation on one side only | authenticated CONFIRM and DONE (8) |
| Nonce reuse and reflection with one shared key | per-direction keys (11.1) |
| Counters restarting at every boot | boot epoch in NVS (11.2) |
| Replays after the receiver reboots | challenge and proof (11.3) |
| Weak randomness: with Wi-Fi and Bluetooth off, `esp_random()` is not a full-entropy source | a SHA-256 pool fed by `esp_random()`, the CPU cycle counter and short dark readings of the LED (ADC noise), refreshed before every pairing. `bootloader_random_enable()` is not used: it takes the same ADC as PacketLED |
| Low-order points | all-zero `ee` or `ss` aborts |
| Timing of MAC checks | constant-time comparison |
| Unknown key share | `ss` in the key (6) |
| OFFER and REVEAL are not authenticated | an attacker can make a pairing fail, nothing more |
| Keys stored in clear in NVS | once the chip has its eFuse key, `NvsPairStorage` seals them under a key derived from it (chips with an HMAC peripheral); on the original ESP32, NVS and flash encryption |
| A flash image copied to another board repeats its epochs | with the chip key, the copy does not open on another chip |
| The saved epoch lost (damaged or deleted) | the saved keys go with it: in clear the peers are erased, sealed the epoch lives in the identity's record and the peers are bound to the identity. A pairing is lost, a nonce is never reused. Pairing again starts the other board's record over (8.5), so messages flow at once |
| An older copy of the flash written back | not detected: an older epoch comes back, so nonces could repeat, and old messages could be accepted again. It takes physical access twice, and a way to read and write the flash |
| Other code run on the same chip (another program, the USB download mode, JTAG) | it can use the chip's key: only secure boot, with download mode and JTAG disabled, prevents that |
| A user who confirms without looking | a press during the SAS does not confirm (8.2); rejecting is one long press |
| A frame longer than the receiver's buffer (ESP-NOW v2 carries up to 1470 bytes) | refused by the transport before anything is copied |
| Pairing over a radio (ESP-NOW, LoRa) | no physical proximity at all: the SAS is the only protection, and the user must compare it |
