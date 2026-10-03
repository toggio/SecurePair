/*
 * SecurePair host tests: crypto against reference vectors, then complete
 * pairings between simulated boards (threads + in-memory transport with
 * losses, lost acknowledgements, dropped and tampered messages), and the NVS
 * storage, in clear and sealed, over a stand-in for Preferences (Preferences.h
 * here).
 *
 * Build and run: run_tests.ps1
 */

#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "SecureLink.h"
#include "SecurePair.h"
#include "internal/Crypto.h"
#include "internal/Datagram.h"
#include "internal/PeerTable.h"
#include "internal/PressDecoder.h"
#include "internal/Protocol.h"
#include "internal/Seal.h"
#include "storage/MemoryPairStorage.h"
#include "storage/NvsPairStorage.h"
#include "vectors.h"

using namespace securepair;

static int failures = 0;
static int checks = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    ++checks;                                                          \
    if (!(cond)) {                                                     \
      ++failures;                                                      \
      printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
    }                                                                  \
  } while (0)

static uint64_t nowUs() {
  static const auto t0 = std::chrono::steady_clock::now();
  return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now() - t0).count();
}

// --- Simulated medium ---------------------------------------------------------

struct Channel {
  struct Item {
    std::vector<uint8_t> data;
    uint32_t atUs;
  };
  std::mutex m;
  std::condition_variable cv;
  std::deque<Item> inbox[2];
  std::mt19937 rng{42};
  double loss = 0, ackLoss = 0;
  // Returns true to drop the message. May modify it.
  std::function<bool(int from, std::vector<uint8_t> &msg)> filter;
  // Returns true if the message is lost but another board in range
  // acknowledges it, as can happen on a broadcast radio.
  std::function<bool(int from, const std::vector<uint8_t> &msg)> strayAck;

  bool chance(double p) {
    std::lock_guard<std::mutex> l(m);
    return std::uniform_real_distribution<double>(0, 1)(rng) < p;
  }
};

class MemTransport : public PairTransport {
 public:
  MemTransport(Channel &ch, int side) : ch_(ch), side_(side) {}

  size_t maxPayload() const override { return 64; }

  bool send(const uint8_t *data, size_t len, bool reliable, SyncMark *mark) override {
    std::vector<uint8_t> msg(data, data + len);
    if (ch_.strayAck && ch_.strayAck(side_, msg)) {
      sleepMs(1);
      if (mark) {
        mark->atUs = (uint32_t)nowUs();
        mark->exact = reliable;
      }
      return true;
    }
    const bool drop = ch_.filter && ch_.filter(side_, msg);
    const int attempts = reliable ? 3 : 1;
    bool delivered = false, acked = false;
    int a = 1;
    for (; a <= attempts; ++a) {
      sleepMs(1);   // air time
      if (!drop && !ch_.chance(ch_.loss)) {
        if (!delivered) {
          std::lock_guard<std::mutex> l(ch_.m);
          ch_.inbox[1 - side_].push_back({msg, (uint32_t)nowUs()});
          ch_.cv.notify_all();
          delivered = true;
        }
        if (!ch_.chance(ch_.ackLoss)) {
          acked = true;
          break;
        }
      }
      if (a < attempts) sleepMs(3);
    }
    if (mark) {
      mark->atUs = (uint32_t)nowUs();
      mark->exact = reliable && acked && a == 1;
    }
    return reliable ? acked : true;
  }

  int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) override {
    std::unique_lock<std::mutex> l(ch_.m);
    auto &q = ch_.inbox[side_];
    if (!ch_.cv.wait_for(l, std::chrono::milliseconds(timeoutMs), [&] { return !q.empty(); }))
      return 0;
    Channel::Item it = q.front();
    q.pop_front();
    if (mark) {
      mark->atUs = it.atUs;
      mark->exact = true;
    }
    const size_t n = it.data.size() < cap ? it.data.size() : cap;
    memcpy(buf, it.data.data(), n);
    return (int)n;
  }

  uint32_t micros() override { return (uint32_t)nowUs(); }
  uint32_t millis() override { return (uint32_t)(nowUs() / 1000); }
  void delayMs(uint32_t ms) override { sleepMs(ms); }
  void pause() override { ++pauses; }
  void resume() override { ++resumes; }
  std::atomic<int> pauses{0}, resumes{0};

  static void sleepMs(uint32_t ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

 private:
  Channel &ch_;
  int side_;
};

// UI that records what it would show.
class FakeUi : public CodeDisplay, public StatusDisplay {
 public:
  void show(const PairCode &sas, uint32_t startUs, uint32_t durationMs) override {
    (void)startUs;
    (void)durationMs;
    sas_ = sas.value;
    sasShown = true;   // returns at once, like a printed number: the engine waits
  }
  void play(StatusPattern ui) override {
    if (ui == StatusPattern::WaitConfirm || ui == StatusPattern::WaitPeerConfirm) waitingConfirm = true;
    if (ui == StatusPattern::Saved) saved = true;
    if (ui == StatusPattern::Error) errors++;
  }
  void reset() {
    sasShown = false;
    waitingConfirm = false;
    saved = false;
    errors = 0;
  }
  std::atomic<uint32_t> sas_{0};
  std::atomic<bool> sasShown{false}, waitingConfirm{false}, saved{false};
  std::atomic<int> errors{0};
};

static PairConfig testConfig() {
  PairConfig c;
  c.alignPauseMs = 20;
  c.rendezvousMs = 5000;
  c.exchangeMs = 10000;
  c.confirmMs = 3000;
  c.offerMinMs = 20;
  c.offerMaxMs = 80;
  c.resendMs = 150;
  c.codeLeadMs = 200;
  c.codeMs = 40;
  c.cycleMs = 200;
  c.uiSlotMs = 20;
  c.sendJitterMs = 50;
  c.commitMs = 800;
  c.pollMs = 5;
  return c;
}

// A board: the storage survives reboot(), everything else is rebuilt.
struct Node {
  MemoryPairStorage storage;
  PairStorage *store = &storage;   // or another storage
  std::unique_ptr<MemTransport> tr;
  FakeUi ui;
  std::unique_ptr<SecurePair> sp;
  PairConfig cfg = testConfig();

  bool boot(Channel &ch, int side) {
    sp.reset();
    tr.reset(new MemTransport(ch, side));
    sp.reset(new SecurePair(*tr, *store, ui, ui));
    return sp->begin(cfg);
  }

  bool record(const PeerId &id, PeerRecord &out) {
    for (size_t i = 0; i < store->capacity(); ++i)
      if (store->loadPeer(i, out) && out.id == id) return true;
    return false;
  }
};

struct Plan {
  bool confirmA = true, confirmB = true;
  bool rejectB = false;
  int confirmDelayA = 0, confirmDelayB = 100;
  int startDelayB = 0;
};

struct Outcome {
  PairResult a, b;
};

static Outcome runPair(Node &A, Node &B, const Plan &p) {
  A.ui.reset();
  B.ui.reset();
  Outcome o{};
  std::atomic<bool> doneA{false}, doneB{false};
  std::thread ta([&] {
    o.a = A.sp->pair(nullptr);
    doneA = true;
  });
  std::thread tb([&] {
    MemTransport::sleepMs(p.startDelayB);
    o.b = B.sp->pair(nullptr);
    doneB = true;
  });
  auto user = [](Node &n, std::atomic<bool> &done, bool confirm, bool reject, int delay) {
    while (!done && !n.ui.waitingConfirm) MemTransport::sleepMs(2);
    if (done) return;
    MemTransport::sleepMs(delay);
    if (reject) n.sp->reject();
    else if (confirm) n.sp->confirm();
  };
  std::thread ua(user, std::ref(A), std::ref(doneA), p.confirmA, false, p.confirmDelayA);
  std::thread ub(user, std::ref(B), std::ref(doneB), p.confirmB, p.rejectB, p.confirmDelayB);
  ta.join();
  tb.join();
  ua.join();
  ub.join();
  return o;
}

static bool inRx(const PeerRecord &r, const uint8_t key[32]) {
  return memcmp(r.key, key, 32) == 0 ||
         ((r.flags & PeerRecord::kHasAlt) && memcmp(r.altKey, key, 32) == 0);
}

// Key each side sends with; alt key accepted too on receive.
static bool canTalk(Node &A, Node &B) {
  PeerRecord ra, rb;
  if (!A.record(B.sp->localId(), ra) || !B.record(A.sp->localId(), rb)) return false;
  return inRx(rb, ra.key) && inRx(ra, rb.key);
}

static bool stable(Node &A, Node &B) {
  PeerRecord ra, rb;
  return A.record(B.sp->localId(), ra) && B.record(A.sp->localId(), rb) && ra.flags == 0 &&
         rb.flags == 0 && memcmp(ra.key, rb.key, 32) == 0 && memcmp(ra.keyId, rb.keyId, 4) == 0;
}

static void hex(const char *label, const uint8_t *p, size_t n) {
  printf("%s", label);
  for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
  printf("\n");
}

// --- Tests ------------------------------------------------------------------

static void testCrypto() {
  printf("crypto vectors\n");
  uint8_t out[80];
  for (const XVec &v : kX25519) {
    CHECK(crypto::x25519(out, v.priv, v.peer));
    CHECK(memcmp(out, v.shared, 32) == 0);
  }
  // RFC 7748 section 6.1
  const uint8_t alicePriv[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                                 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                                 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
  const uint8_t alicePub[32] = {0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
                                0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
                                0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
  const uint8_t nine[32] = {9};
  CHECK(crypto::x25519(out, alicePriv, nine));
  CHECK(memcmp(out, alicePub, 32) == 0);
  // Low-order point (all zero result) is refused.
  const uint8_t zero[32] = {};
  CHECK(!crypto::x25519(out, alicePriv, zero));

  for (const GVec &v : kGcm) {
    uint8_t ct[70], tag[16], pt[70];
    CHECK(crypto::gcmEncrypt(v.key, v.iv, v.aad, v.aadLen, v.pt, v.len, ct, tag));
    CHECK(memcmp(ct, v.ct, v.len) == 0);
    CHECK(memcmp(tag, v.tag, 16) == 0);
    CHECK(crypto::gcmDecrypt(v.key, v.iv, v.aad, v.aadLen, v.ct, v.len, pt, v.tag));
    CHECK(memcmp(pt, v.pt, v.len) == 0);
    uint8_t bad[16];
    memcpy(bad, v.tag, 16);
    bad[3] ^= 1;
    CHECK(!crypto::gcmDecrypt(v.key, v.iv, v.aad, v.aadLen, v.ct, v.len, pt, bad));
  }

  const size_t lens[3] = {0, 55, 200};
  for (int i = 0; i < 3; ++i) {
    crypto::sha256(kShaMsg, lens[i], out);
    CHECK(memcmp(out, kShaDigest[i], 32) == 0);
  }
  crypto::Sha256 s;   // incremental, odd chunks
  for (size_t off = 0; off < 200; off += 7) s.update(kShaMsg + off, off + 7 <= 200 ? 7 : 200 - off);
  s.finish(out);
  CHECK(memcmp(out, kShaDigest[2], 32) == 0);

  crypto::hmacSha256(kHmacKey, 20, kShaMsg, 200, out);
  CHECK(memcmp(out, kHmac[0], 32) == 0);
  crypto::hmacSha256(kHmacKey, 100, kShaMsg, 10, out);
  CHECK(memcmp(out, kHmac[1], 32) == 0);

  uint8_t prk[32];
  crypto::hkdfExtract(kHkdfSalt, 32, kHkdfIkm, 64, prk);
  CHECK(memcmp(prk, kHkdfPrk, 32) == 0);
  crypto::hkdfExpand(prk, "link test", out, 80);
  CHECK(memcmp(out, kHkdfOkm, 80) == 0);
}

static void testKeySchedule() {
  printf("key schedule\n");
  uint8_t aPriv[32], aPub[32], bPriv[32], bPub[32], na[16], nb[16], xid[8], c[32];
  crypto::x25519Keypair(aPriv, aPub);
  crypto::x25519Keypair(bPriv, bPub);
  crypto::randomBytes(na, 16);
  crypto::randomBytes(nb, 16);
  crypto::randomBytes(xid, 8);
  proto::commitment(xid, aPub, na, c);
  proto::Stage1 sa, sb;
  CHECK(proto::deriveStage1(xid, c, aPriv, aPub, na, bPub, nb, sa));
  CHECK(proto::deriveStage1(xid, c, bPriv, bPub, nb, aPub, na, sb));
  CHECK(sa.selfIsLo != sb.selfIsLo);
  CHECK(memcmp(sa.th1, sb.th1, 32) == 0);
  CHECK(sa.sas.value == sb.sas.value);
  CHECK(sa.sas.value < (1u << kCodeBits));
  CHECK(memcmp(sa.hsSelf, sb.hsPeer, 32) == 0 && memcmp(sa.hsPeer, sb.hsSelf, 32) == 0);
  CHECK(memcmp(sa.hsSelf, sa.hsPeer, 32) != 0);
  // Reflection: own key as the peer's.
  proto::Stage1 sr;
  CHECK(!proto::deriveStage1(xid, c, aPriv, aPub, na, aPub, na, sr));

  uint8_t iaPriv[32], iaPub[32], ibPriv[32], ibPub[32];
  crypto::x25519Keypair(iaPriv, iaPub);
  crypto::x25519Keypair(ibPriv, ibPub);
  proto::Stage2 ta, tb;
  CHECK(proto::deriveStage2(sa, iaPriv, iaPub, ibPub, ta));
  CHECK(proto::deriveStage2(sb, ibPriv, ibPub, iaPub, tb));
  CHECK(memcmp(ta.linkKey, tb.linkKey, 32) == 0);
  CHECK(memcmp(ta.keyId, tb.keyId, 4) == 0);
  CHECK(memcmp(ta.cfSelf, tb.cfPeer, 32) == 0);
  // Somebody claiming B's identity without B's private key gets another key.
  uint8_t fakePriv[32], fakePub[32];
  crypto::x25519Keypair(fakePriv, fakePub);
  proto::Stage2 tf;
  CHECK(proto::deriveStage2(sb, fakePriv, ibPub, iaPub, tf));
  CHECK(memcmp(tf.linkKey, ta.linkKey, 32) != 0);

  PeerId ia, ib;
  proto::peerIdFromPub(iaPub, ia);
  proto::peerIdFromPub(ibPub, ib);
  uint8_t k1[32], k2[32], k3[32];
  proto::directionalKey(ta.linkKey, ia, ib, k1);
  proto::directionalKey(tb.linkKey, ia, ib, k2);
  proto::directionalKey(ta.linkKey, ib, ia, k3);
  CHECK(memcmp(k1, k2, 32) == 0);
  CHECK(memcmp(k1, k3, 32) != 0);
}

static void testFirstPairAndRepair() {
  printf("first pairing, reboot, re-pairing\n");
  Channel ch;
  Node A, B;
  CHECK(A.boot(ch, 0) && B.boot(ch, 1));
  CHECK(!A.sp->hasPeer() && !B.sp->hasPeer());
  CHECK(!(A.sp->localId() == B.sp->localId()));

  Outcome o = runPair(A, B, Plan());
  CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok);
  CHECK(A.ui.sas_ == B.ui.sas_);
  CHECK(stable(A, B));
  CHECK(A.sp->peerCount() == 1 && B.sp->peerCount() == 1);
  PeerRecord r1;
  CHECK(A.record(B.sp->localId(), r1));

  // Reboot: identity and peers survive, the epoch moves on.
  const PeerId idA = A.sp->localId();
  const uint32_t epochA = A.sp->epoch();
  CHECK(A.boot(ch, 0) && B.boot(ch, 1));
  CHECK(A.sp->localId() == idA);
  CHECK(A.sp->epoch() == epochA + 1);
  CHECK(A.sp->hasPeer() && A.sp->repairWindowOpen());

  o = runPair(A, B, Plan());
  CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok);
  CHECK(stable(A, B));
  PeerRecord r2;
  CHECK(A.record(B.sp->localId(), r2));
  CHECK(memcmp(r1.key, r2.key, 32) != 0);
  CHECK(A.sp->peerCount() == 1);
}

static void testNotConfirmed() {
  printf("one side does not confirm / rejects\n");
  Channel ch;
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  // Whichever board times out first tells the other, which may then end with
  // Rejected: either way, nothing is saved.
  auto timedOut = [](const Outcome &o) {
    auto either = [](PairResult r) { return r == PairResult::Timeout || r == PairResult::Rejected; };
    return either(o.a) && either(o.b) && (o.a == PairResult::Timeout || o.b == PairResult::Timeout);
  };
  Plan p;
  p.confirmB = false;
  Outcome o = runPair(A, B, p);
  CHECK(timedOut(o));
  CHECK(!A.sp->hasPeer() && !B.sp->hasPeer());

  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  PeerRecord before;
  CHECK(A.record(B.sp->localId(), before));

  p = Plan();
  p.confirmA = true;
  p.confirmB = false;   // re-pairing, B never confirms
  o = runPair(A, B, p);
  CHECK(timedOut(o));
  PeerRecord after;
  CHECK(A.record(B.sp->localId(), after) && memcmp(after.key, before.key, 32) == 0 && after.flags == 0);
  CHECK(stable(A, B));

  p = Plan();
  p.rejectB = true;
  o = runPair(A, B, p);
  CHECK(o.a == PairResult::Rejected && o.b == PairResult::Rejected);
  CHECK(A.record(B.sp->localId(), after) && memcmp(after.key, before.key, 32) == 0);
  CHECK(stable(A, B));
}

static void testTamper() {
  printf("tampered messages\n");
  for (uint8_t type : {proto::kReveal, proto::kIdent}) {
    Channel ch;
    Node A, B;
    A.boot(ch, 0);
    B.boot(ch, 1);
    std::atomic<bool> done{false};
    ch.filter = [&](int, std::vector<uint8_t> &m) {
      if (!done && m.size() > 20 && m[1] == type) {
        m[20] ^= 0x40;
        done = true;
      }
      return false;
    };
    Outcome o = runPair(A, B, Plan());
    CHECK(o.a != PairResult::Ok || o.b != PairResult::Ok);
    CHECK(o.a == PairResult::ProtocolError || o.b == PairResult::ProtocolError);
    CHECK(!A.sp->hasPeer() && !B.sp->hasPeer());
  }
}

static void testLostDone() {
  printf("DONE never arrives (convergence)\n");
  Channel ch;
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  PeerRecord oldA;
  A.record(B.sp->localId(), oldA);

  // A confirms first; B's DONE arrives, A's DONE never does.
  ch.filter = [](int from, std::vector<uint8_t> &m) { return from == 0 && m[1] == proto::kDone; };
  Plan p;
  p.confirmDelayA = 0;
  p.confirmDelayB = 300;
  Outcome o = runPair(A, B, p);
  CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok);
  PeerRecord ra, rb;
  CHECK(A.record(B.sp->localId(), ra) && B.record(A.sp->localId(), rb));
  // A knows B saved: sends with the new key, still accepts the old one.
  CHECK(ra.flags == PeerRecord::kHasAlt && memcmp(ra.altKey, oldA.key, 32) == 0);
  // B does not know whether A saved: keeps sending with the old key.
  CHECK(rb.flags == (PeerRecord::kHasAlt | PeerRecord::kAltIsNew) && memcmp(rb.key, oldA.key, 32) == 0);
  CHECK(canTalk(A, B));

  // A later re-pairing cleans everything up.
  ch.filter = nullptr;
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  CHECK(stable(A, B));
}

static void testLossy() {
  printf("lossy channel (20%% frames, 15%% acks lost)\n");
  Channel ch;
  ch.rng.seed(7);
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  ch.loss = 0.20;
  ch.ackLoss = 0.15;
  int ok = 0, fail = 0;
  for (int i = 0; i < 25; ++i) {
    Plan p;
    p.startDelayB = (i % 5) * 60;
    p.confirmDelayA = (i % 3) * 150;
    p.confirmDelayB = (i % 4) * 120;
    Outcome o = runPair(A, B, p);
    (o.a == PairResult::Ok && o.b == PairResult::Ok) ? ++ok : ++fail;
    // Whatever happened, the two boards can still talk to each other.
    CHECK(canTalk(A, B));
    // Cleanup round on a clean channel before the next lossy one.
    ch.loss = ch.ackLoss = 0;
    CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
    CHECK(stable(A, B));
    ch.loss = 0.20;
    ch.ackLoss = 0.15;
  }
  printf("  %d/%d lossy pairings completed, %d failed cleanly\n", ok, ok + fail, fail);
  CHECK(ok >= 15);
}

static void testMultiPeerAndFull() {
  printf("N:N and storage full\n");
  Channel ab, ac;
  Node A, B, C;
  A.cfg.maxPeers = 2;
  A.boot(ab, 0);
  B.boot(ab, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  A.boot(ac, 0);   // A now faces C
  C.boot(ac, 1);
  Outcome oc = runPair(A, C, Plan());
  CHECK(oc.a == PairResult::Ok && oc.b == PairResult::Ok);
  if (oc.a != PairResult::Ok || oc.b != PairResult::Ok)
    printf("  A: %s, C: %s\n", SecurePair::resultText(oc.a), SecurePair::resultText(oc.b));
  CHECK(A.sp->peerCount() == 2 && C.sp->peerCount() == 1);
  CHECK(stable(A, C));
  PeerRecord rb;
  CHECK(A.record(B.sp->localId(), rb));

  // Third peer: A is full and says so before the SAS.
  Channel ad;
  Node D;
  A.boot(ad, 0);
  D.boot(ad, 1);
  Outcome o = runPair(A, D, Plan());
  CHECK(o.a == PairResult::StorageFull && o.b == PairResult::StorageFull);
  if (o.a != PairResult::StorageFull || o.b != PairResult::StorageFull)
    printf("  A: %s, D: %s\n", SecurePair::resultText(o.a), SecurePair::resultText(o.b));
  CHECK(!A.ui.sasShown && !D.ui.sasShown);
  CHECK(!D.sp->hasPeer() && A.sp->peerCount() == 2);

  // Re-pairing a known peer still works when full.
  A.boot(ac, 0);
  C.boot(ac, 1);
  oc = runPair(A, C, Plan());
  CHECK(oc.a == PairResult::Ok && oc.b == PairResult::Ok);
  if (oc.a != PairResult::Ok || oc.b != PairResult::Ok)
    printf("  A: %s, C: %s\n", SecurePair::resultText(oc.a), SecurePair::resultText(oc.b));
  CHECK(A.sp->peerCount() == 2);
}

static void testStorageFailure() {
  printf("storage write failure\n");
  {
    // begin() failed: no pairing can start.
    Channel c;
    Node X;
    X.storage.failWrites = true;
    CHECK(!X.boot(c, 0));
    CHECK(X.sp->pair(nullptr) == PairResult::StorageError);
    CHECK(!X.sp->requestPairing() && !X.sp->handle(PairButton::Long));
  }
  Channel ch;
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  A.storage.failWrites = true;
  Outcome o = runPair(A, B, Plan());
  CHECK(o.a == PairResult::StorageError);
  CHECK(!A.sp->hasPeer());
  A.storage.failWrites = false;
  // B either never saved or rolled back after A's ABORT.
  CHECK(!B.sp->hasPeer());
}


static void inject(Channel &ch, int toSide, const std::vector<uint8_t> &msg) {
  std::lock_guard<std::mutex> l(ch.m);
  ch.inbox[toSide].push_back({msg, (uint32_t)nowUs()});
  ch.cv.notify_all();
}

static void testSecureLink() {
  printf("SecureLink\n");
  Channel ch;
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  const PeerId idA = A.sp->localId(), idB = B.sp->localId();

  std::vector<uint8_t> lastFromA;
  ch.filter = [&](int from, std::vector<uint8_t> &m) {
    if (from == 0 && m[0] == SecureLink::kTypeData) lastFromA = m;
    return false;
  };

  std::unique_ptr<SecureLink> la(new SecureLink(*A.sp)), lb(new SecureLink(*B.sp));
  CHECK(la->maxPayload() == 35);
  uint8_t buf[64];
  PeerId from = {};

  CHECK(la->send(idB, "hello") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 5 && memcmp(buf, "hello", 5) == 0 && from == idA);
  CHECK(lb->send(idA, "hi A") == SecureLink::SendResult::Ok);
  CHECK(la->receive(buf, sizeof(buf), from, 100) == 4 && from == idB);
  CHECK(lastFromA.size() == 5 + SecureLink::kOverhead);

  // Replay of the same frame.
  inject(ch, 1, lastFromA);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().replayed == 1);

  // Tampered ciphertext / header.
  CHECK(la->send(idB, "second") == SecureLink::SendResult::Ok);
  std::vector<uint8_t> t = lastFromA;
  lb->receive(buf, sizeof(buf), from, 100);
  t[SecureLink::kHeaderLen + 1] ^= 1;
  t[12] ^= 0x80;   // counter changed too, so it is not a replay
  inject(ch, 1, t);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().badAuth == 1);

  // Reflection: A's own frame sent back to A.
  lastFromA[12] ^= 0x40;
  inject(ch, 0, lastFromA);
  CHECK(la->receive(buf, sizeof(buf), from, 100) == 0 && la->stats().badAuth == 1);

  // Lengths.
  uint8_t big[40] = {};
  CHECK(la->send(idB, big, 36) == SecureLink::SendResult::BadLength);
  CHECK(la->send(idB, big, 0) == SecureLink::SendResult::BadLength);
  CHECK(la->send(idB, big, 35) == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 35);
  CHECK(la->send(idB, "x") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, 0, from, 100) == 0 && lb->stats().tooLong == 1);
  PeerId stranger = {{1, 2, 3, 4, 5, 6, 7, 8}};
  CHECK(la->send(stranger, "x") == SecureLink::SendResult::UnknownPeer);

  // Sender reboot: counter restarts, the epoch moves on, the receiver accepts
  // and saves the new epoch.
  CHECK(la->send(idB, "old epoch") == SecureLink::SendResult::Ok);
  lb->receive(buf, sizeof(buf), from, 100);
  const std::vector<uint8_t> oldFrame = lastFromA;
  la.reset();
  A.boot(ch, 0);
  la.reset(new SecureLink(*A.sp));
  CHECK(la->send(idB, "new epoch") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 9);
  PeerRecord rb;
  CHECK(B.record(idA, rb) && rb.rxEpoch == A.sp->epoch());

  // Receiver reboot: a frame from an older epoch is still refused.
  lb.reset();
  B.boot(ch, 1);
  lb.reset(new SecureLink(*B.sp));
  inject(ch, 1, oldFrame);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().replayed == 1);

  // ... and a frame of A's current epoch cannot be judged: refused, challenge,
  // proof, then messages flow. The refused one is not delivered later.
  const std::vector<uint8_t> beforeReboot = lastFromA;   // "new epoch", already delivered once
  inject(ch, 1, beforeReboot);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().refused == 1);
  CHECK(!lb->synced(idA));
  CHECK(la->receive(buf, sizeof(buf), from, 100) == 0 && la->stats().proofs == 1);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->synced(idA));
  inject(ch, 1, beforeReboot);   // still a replay after the proof
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().replayed == 2);
  CHECK(la->send(idB, "after") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 5);

  // sync() at start-up: no message is refused.
  lb.reset();
  B.boot(ch, 1);
  lb.reset(new SecureLink(*B.sp));
  CHECK(lb->sync() == 1);
  CHECK(la->receive(buf, sizeof(buf), from, 100) == 0 && la->stats().proofs == 2);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->synced(idA));
  CHECK(la->send(idB, "direct") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 6 && lb->stats().refused == 0);

  // One-way links may skip the challenge.
  lb.reset();
  B.boot(ch, 1);
  lb.reset(new SecureLink(*B.sp));
  lb->requireFreshness(false);
  CHECK(la->send(idB, "one way") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 7);

  // A frame sent under the old key but not delivered yet (it will arrive late).
  std::vector<uint8_t> late;
  ch.filter = [&](int from2, std::vector<uint8_t> &m) {
    if (from2 == 0 && m[0] == SecureLink::kTypeData) late = m;
    return from2 == 0 && m[0] == SecureLink::kTypeData;
  };
  la->send(idB, "late");
  CHECK(!late.empty());

  // A re-pairing whose last DONE was lost is completed by traffic.
  ch.filter = [](int from2, std::vector<uint8_t> &m) { return from2 == 0 && m[1] == proto::kDone; };
  Plan p;
  p.confirmDelayB = 300;
  CHECK(runPair(A, B, p).a == PairResult::Ok);
  ch.filter = nullptr;
  PeerRecord ra;
  CHECK(A.record(idB, ra) && ra.flags == PeerRecord::kHasAlt);
  CHECK(B.record(idA, rb) && (rb.flags & PeerRecord::kAltIsNew));
  inject(ch, 1, late);                                                   // old key, arriving late
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 4);                  // delivered...
  CHECK(B.record(idA, rb) && (rb.flags & PeerRecord::kAltIsNew));        // ...and the new key is kept
  CHECK(la->send(idB, "new key") == SecureLink::SendResult::Ok);          // A uses the new key
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 7);                  // B promotes it
  CHECK(B.record(idA, rb) && rb.flags == 0 && memcmp(rb.key, ra.key, 32) == 0);
  CHECK(lb->send(idA, "ok") == SecureLink::SendResult::Ok);               // B now sends with it
  CHECK(la->receive(buf, sizeof(buf), from, 100) == 2);                  // A drops the old one
  CHECK(stable(A, B));
  CHECK(lb->stats().keyUpdates == 1 && la->stats().keyUpdates == 1);
}

// A proof held back on the way, and an epoch that could not be saved: no
// message is delivered twice.
static void testReplayEdges() {
  printf("SecureLink: a delayed proof, an epoch not saved\n");
  Channel ch;
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  const PeerId idB = B.sp->localId();
  uint8_t buf[64];
  PeerId from = {};
  std::unique_ptr<SecureLink> la(new SecureLink(*A.sp)), lb(new SecureLink(*B.sp));
  CHECK(la->send(idB, "first") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 5);

  // Both reboot. B challenges A, and A's proof is held back.
  la.reset();
  lb.reset();
  CHECK(A.boot(ch, 0) && B.boot(ch, 1));
  la.reset(new SecureLink(*A.sp));
  lb.reset(new SecureLink(*B.sp));
  std::vector<uint8_t> proof, cmd;
  ch.filter = [&](int side, std::vector<uint8_t> &m) {
    if (side != 0) return false;
    if (m[0] == SecureLink::kTypeProof && proof.empty()) {
      proof = m;
      return true;
    }
    if (m[0] == SecureLink::kTypeData) cmd = m;
    return false;
  };
  CHECK(lb->sync() == 1);
  CHECK(la->receive(buf, sizeof(buf), from, 100) == 0 && !proof.empty());
  // A's new boot: its first command is delivered at once...
  CHECK(la->send(idB, "open") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 4);
  // ...then the proof comes late. It must not move the window back.
  inject(ch, 1, proof);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0);
  inject(ch, 1, cmd);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().replayed == 1);
  CHECK(la->send(idB, "next") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 4);

  // A reboots; B cannot save A's new epoch, so it does not deliver.
  la.reset();
  CHECK(A.boot(ch, 0));
  la.reset(new SecureLink(*A.sp));
  B.storage.failWrites = true;
  CHECK(la->send(idB, "cmd") == SecureLink::SendResult::Ok);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().notSaved == 1);
  B.storage.failWrites = false;
  // After B's reboot the recorded frame is delivered once, now that the epoch
  // is saved, and never again.
  lb.reset();
  CHECK(B.boot(ch, 1));
  lb.reset(new SecureLink(*B.sp));
  inject(ch, 1, cmd);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 3);
  inject(ch, 1, cmd);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0);
  lb.reset();
  CHECK(B.boot(ch, 1));
  lb.reset(new SecureLink(*B.sp));
  inject(ch, 1, cmd);
  CHECK(lb->receive(buf, sizeof(buf), from, 100) == 0 && lb->stats().refused == 1);
  ch.filter = nullptr;
}

static void drain(Channel &ch) {
  std::lock_guard<std::mutex> l(ch.m);
  ch.inbox[0].clear();
  ch.inbox[1].clear();
}

// One message from one board to the other, on a quiet channel.
static bool talk(Channel &ch, Node &from, Node &to) {
  drain(ch);
  SecureLink lf(*from.sp), lt(*to.sp);
  uint8_t buf[16];
  PeerId who = {};
  return lf.send(to.sp->localId(), "hi") == SecureLink::SendResult::Ok &&
         lt.receive(buf, sizeof(buf), who, 100) == 2 && who == from.sp->localId();
}

// Paired, then a re-pairing whose last DONE, A's, is lost: A sends with the new
// key and still accepts the old one; B sends with the old key, the new one pending.
static void repairLosingDoneA(Channel &ch, Node &A, Node &B) {
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  ch.filter = [](int side, std::vector<uint8_t> &m) {
    return side == 0 && m[0] == kProtocolVersion && m[1] == proto::kDone;
  };
  Plan p;
  p.confirmDelayB = 300;
  const Outcome o = runPair(A, B, p);
  ch.filter = nullptr;
  CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok);
  PeerRecord ra, rb;
  CHECK(A.record(B.sp->localId(), ra) && ra.flags == PeerRecord::kHasAlt);
  CHECK(B.record(A.sp->localId(), rb) && (rb.flags & PeerRecord::kAltIsNew));
}

// Two re-pairings cut short in a row, before any message: the boards can
// still talk, in both directions, whoever confirms first.
static void testRepairCutTwice() {
  printf("two re-pairings cut short in a row\n");
  const int delays[][2] = {{0, 0}, {0, 150}, {150, 0}, {0, 0}};
  for (const auto &d : delays) {
    Channel ch;
    Node A, B;
    A.cfg.confirmMs = B.cfg.confirmMs = 1500;
    A.boot(ch, 0);
    B.boot(ch, 1);
    repairLosingDoneA(ch, A, B);

    // Second, before any message: every DONE is lost.
    ch.filter = [](int, std::vector<uint8_t> &m) {
      return m[0] == kProtocolVersion && m[1] == proto::kDone;
    };
    Plan p;
    p.confirmDelayA = d[0];
    p.confirmDelayB = d[1];
    runPair(A, B, p);
    ch.filter = nullptr;
    CHECK(canTalk(A, B));
    CHECK(talk(ch, B, A));   // B first: the direction that broke
    CHECK(talk(ch, A, B));
  }
}

// B is a key behind (repairLosingDoneA). A must keep the key B sends with until
// B's DONE shows that B has saved: an acknowledgement of A's CONFIRM does not.
static void testRepairPeerBehind() {
  printf("re-pairing a board a key behind: stray acknowledgement, failed write\n");
  const auto doneOrAbort = [](int, std::vector<uint8_t> &m) {
    return m[0] == kProtocolVersion && (m[1] == proto::kDone || m[1] == proto::kAbort);
  };
  {
    // A's CONFIRM never reaches B, but another board in range acknowledges it.
    Channel ch;
    Node A, B;
    A.cfg.confirmMs = B.cfg.confirmMs = 1500;
    A.boot(ch, 0);
    B.boot(ch, 1);
    repairLosingDoneA(ch, A, B);
    ch.filter = doneOrAbort;
    ch.strayAck = [](int side, const std::vector<uint8_t> &m) {
      return side == 0 && m[0] == kProtocolVersion && m[1] == proto::kConfirm;
    };
    Plan p;
    p.confirmDelayB = 0;
    runPair(A, B, p);
    ch.filter = nullptr;
    ch.strayAck = nullptr;
    CHECK(canTalk(A, B));
    CHECK(talk(ch, B, A));
    CHECK(talk(ch, A, B));
  }
  {
    // B takes A's CONFIRM, then cannot save; its ABORT is lost.
    Channel ch;
    Node A, B;
    A.cfg.confirmMs = B.cfg.confirmMs = 1500;
    A.boot(ch, 0);
    B.boot(ch, 1);
    repairLosingDoneA(ch, A, B);
    ch.filter = doneOrAbort;
    B.storage.failWrites = true;
    Plan p;
    p.confirmDelayB = 0;
    const Outcome o = runPair(A, B, p);
    B.storage.failWrites = false;
    ch.filter = nullptr;
    CHECK(o.b == PairResult::StorageError && o.a != PairResult::Ok);
    CHECK(canTalk(A, B));
    CHECK(talk(ch, B, A));
    CHECK(talk(ch, A, B));
  }
}

// The last DONE is acknowledged, but not by the peer, or the peer takes it and
// cannot save the change. The board that sent it must keep the old key, which
// the peer still sends with, until the peer moves to the new one.
static void testDropOldKey() {
  printf("dropping the old key: stray acknowledgement, failed write\n");
  for (int variant = 0; variant < 2; ++variant) {
    Channel ch;
    Node A, B;
    A.boot(ch, 0);
    B.boot(ch, 1);
    CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
    if (variant == 0) {
      // A's DONE never reaches B, but another board in range acknowledges it.
      ch.strayAck = [](int side, const std::vector<uint8_t> &m) {
        return side == 0 && m[0] == kProtocolVersion && m[1] == proto::kDone;
      };
    } else {
      // B takes A's DONE, then cannot save the new key as the one it sends with.
      ch.filter = [&](int side, std::vector<uint8_t> &m) {
        if (side == 0 && m[0] == kProtocolVersion && m[1] == proto::kDone) B.storage.failWrites = true;
        return false;
      };
    }
    Plan p;
    p.confirmDelayB = 300;   // B saves first, A last
    const Outcome o = runPair(A, B, p);
    ch.strayAck = nullptr;
    ch.filter = nullptr;
    B.storage.failWrites = false;
    CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok);
    CHECK(canTalk(A, B));
    CHECK(talk(ch, B, A));   // still with the old key
    CHECK(talk(ch, A, B));   // the new key: B moves to it
    CHECK(talk(ch, B, A) && stable(A, B));
  }
}

// The key replacement rules, one by one.
static void testPeerTable() {
  printf("peer table rules\n");
  MemoryPairStorage st;
  PeerTable t(st);
  CHECK(t.load(8));
  const PeerId id = {{1, 2, 3, 4, 5, 6, 7, 8}};
  uint8_t pub[32] = {1}, k0[32] = {10}, k1[32] = {11}, k2[32] = {12};
  const uint8_t i0[4] = {0, 0, 0, 10}, i1[4] = {0, 0, 0, 11}, i2[4] = {0, 0, 0, 12};
  PeerTable::Undo u;
  PeerRecord r;
  CHECK(t.saveCandidate(id, pub, k0, i0, true, nullptr, 1, u) && t.raiseRxEpoch(id, 5));

  // The peer still sends with K0: a plain rotation, the saved epoch kept.
  CHECK(t.saveCandidate(id, pub, k1, i1, false, i0, 1, u));
  CHECK(t.find(id, r) && memcmp(r.keyId, i0, 4) == 0 && memcmp(r.altKeyId, i1, 4) == 0 &&
        (r.flags & PeerRecord::kAltIsNew) && r.rxEpoch == 5);
  // Undone after the epoch went up meanwhile: the higher epoch stays.
  CHECK(t.raiseRxEpoch(id, 7) && t.rollback(u));
  CHECK(t.find(id, r) && r.flags == 0 && memcmp(r.keyId, i0, 4) == 0 && r.rxEpoch == 7);

  // K1 pending here, and the peer already sends with it: settled, then rotated.
  CHECK(t.saveCandidate(id, pub, k1, i1, false, i0, 1, u));
  CHECK(t.saveCandidate(id, pub, k2, i2, false, i1, 1, u));
  CHECK(t.find(id, r) && memcmp(r.keyId, i1, 4) == 0 && memcmp(r.altKeyId, i2, 4) == 0 &&
        (r.flags & PeerRecord::kAltIsNew) && r.rxEpoch == 7);

  // The peer has none of our keys (it lost its records): start over, epoch too.
  CHECK(t.saveCandidate(id, pub, k0, i0, false, nullptr, 1, u));
  CHECK(t.find(id, r) && memcmp(r.keyId, i0, 4) == 0 && r.flags == PeerRecord::kUnproven &&
        r.rxEpoch == 0);
  CHECK(t.rollback(u) && t.find(id, r) && memcmp(r.keyId, i1, 4) == 0 && r.rxEpoch == 7);
  const uint8_t stranger[4] = {9, 9, 9, 9};
  CHECK(t.saveCandidate(id, pub, k0, i0, true, stranger, 1, u));
  CHECK(t.find(id, r) && memcmp(r.keyId, i0, 4) == 0 && r.flags == 0 && r.rxEpoch == 0);
}

// Pairing on one medium, messages on another (e.g. LEDs, then ESP-NOW).
static void testSecondTransport() {
  printf("SecureLink on a second transport\n");
  Channel optical, radio;
  Node A, B;
  A.boot(optical, 0);
  B.boot(optical, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  MemTransport ra(radio, 0), rb(radio, 1);
  SecureLink la(*A.sp, ra), lb(*B.sp, rb);
  CHECK(la.maxPayload() == 64 - SecureLink::kOverhead);
  uint8_t buf[64];
  PeerId from = {};
  CHECK(la.send(B.sp->localId(), "over the radio") == SecureLink::SendResult::Ok);
  CHECK(lb.receive(buf, sizeof(buf), from, 100) == 14 && from == A.sp->localId());
  // Nothing went over the pairing medium.
  CHECK(optical.inbox[0].empty() && optical.inbox[1].empty());

  // A second link on the pairing medium, next to the radio one: they share
  // counters (no nonce is ever reused) and the replay window (a frame accepted
  // over one medium is refused over the other).
  MemTransport oa(optical, 0), ob(optical, 1);
  SecureLink la2(*A.sp, oa), lb2(*B.sp, ob);
  std::vector<uint8_t> overRadio, overOptical;
  radio.filter = [&](int from, std::vector<uint8_t> &m) {
    if (from == 0 && m[0] == SecureLink::kTypeData) overRadio = m;
    return false;
  };
  optical.filter = [&](int from, std::vector<uint8_t> &m) {
    if (from == 0 && m[0] == SecureLink::kTypeData) overOptical = m;
    return false;
  };
  CHECK(la.send(B.sp->localId(), "radio") == SecureLink::SendResult::Ok);
  CHECK(la2.send(B.sp->localId(), "light") == SecureLink::SendResult::Ok);
  CHECK(!overRadio.empty() && !overOptical.empty());
  CHECK(memcmp(overRadio.data() + 5, overOptical.data() + 5, 8) != 0);   // different nonces
  CHECK(lb.receive(buf, sizeof(buf), from, 100) == 5);
  CHECK(lb2.receive(buf, sizeof(buf), from, 100) == 5);
  inject(radio, 1, overOptical);                                        // the light frame, by radio
  CHECK(lb.receive(buf, sizeof(buf), from, 100) == 0 && lb.stats().replayed == 1);
}

// ESP-NOW framing, acknowledgements and duplicate filter (internal/Datagram).
static void testDatagram() {
  printf("datagram framing (ESP-NOW)\n");
  const uint8_t me[6] = {1, 2, 3, 4, 5, 6}, other[6] = {9, 9, 9, 9, 9, 9};
  uint8_t f[250];
  const uint8_t payload[3] = {7, 8, 9};
  size_t n = dgram::buildData(f, 0xBEEF, payload, 3);
  dgram::Frame fr;
  CHECK(n == 7 && dgram::parse(f, n, 246, fr) && fr.kind == dgram::kData && fr.seq == 0xBEEF &&
        fr.len == 3 && memcmp(fr.payload, payload, 3) == 0);
  n = dgram::buildAck(f, 0xBEEF, me);
  CHECK(dgram::parse(f, n, 246, fr) && fr.kind == dgram::kAck && memcmp(fr.dest, me, 6) == 0);
  CHECK(!dgram::parse(f, n - 1, 246, fr));     // truncated ack
  f[0] ^= 1;
  CHECK(!dgram::parse(f, n, 246, fr));         // not ours (e.g. a SecureLink frame)
  CHECK(!dgram::parse(f, 4, 246, fr));         // empty data

  // Data carrying its source address (LoRa).
  n = dgram::buildDataFrom(f, 7, other, payload, 3);
  CHECK(dgram::parse(f, n, 245, fr) && fr.kind == dgram::kDataFrom && fr.seq == 7 &&
        memcmp(fr.src, other, 6) == 0 && fr.len == 3 && memcmp(fr.payload, payload, 3) == 0);
  CHECK(!dgram::parse(f, dgram::kHeaderLen + 6, 245, fr));   // no payload

  // Longer than the receiver's buffer, as ESP-NOW v2 frames can be: refused.
  static uint8_t big[1470], body[1470];
  n = dgram::buildData(big, 1, body, 296);
  CHECK(!dgram::parse(big, n, 246, fr));
  CHECK(dgram::parse(big, dgram::kHeaderLen + 246, 246, fr) && fr.len == 246);
  n = dgram::buildDataFrom(big, 1, other, body, 246);
  CHECK(!dgram::parse(big, n, 245, fr));

  dgram::Dedup d;
  CHECK(!d.duplicate(me, 1));
  d.remember(me, 1);
  CHECK(d.duplicate(me, 1) && !d.duplicate(me, 2) && !d.duplicate(other, 1));
  d.remember(me, 2);
  CHECK(!d.duplicate(me, 1) && d.duplicate(me, 2));
  // Many senders: the oldest entry is reused, nobody else is disturbed.
  for (uint8_t i = 0; i < 20; ++i) {
    const uint8_t s[6] = {i, i, i, i, i, i};
    d.remember(s, i);
    CHECK(d.duplicate(s, i));
  }
}

static void testNonBlocking() {
  printf("requestPairing() in a task, repair window\n");
  Channel ch;
  Node A, B;
  A.cfg.repairWindowMs = 300;
  A.boot(ch, 0);
  B.boot(ch, 1);
  CHECK(A.sp->requestPairing());       // no peers: always allowed
  CHECK(!A.sp->requestPairing());      // already running
  CHECK(A.sp->busy());
  std::thread tb([&] { B.sp->pair(nullptr); });
  while (!A.ui.waitingConfirm || !B.ui.waitingConfirm) MemTransport::sleepMs(2);
  A.sp->confirm();
  B.sp->confirm();
  tb.join();
  while (A.sp->busy()) MemTransport::sleepMs(2);
  CHECK(A.sp->lastResult() == PairResult::Ok);
  CHECK(stable(A, B));

  A.boot(ch, 0);
  CHECK(A.sp->repairWindowOpen());
  MemTransport::sleepMs(350);
  CHECK(!A.sp->repairWindowOpen());
  CHECK(!A.sp->requestPairing());
}

// handle(): the one call in loop().
static void testHandle() {
  printf("handle(), pauseDuringPairing()\n");
  Channel ch, radioCh;
  Node A, B;
  A.boot(ch, 0);
  B.boot(ch, 1);
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  A.boot(ch, 0);
  B.boot(ch, 1);
  A.ui.reset();
  B.ui.reset();
  MemTransport radio(radioCh, 0);
  A.sp->pauseDuringPairing(radio);
  A.sp->pauseDuringPairing(radio);                   // twice: registered once

  CHECK(!A.sp->handle(PairButton::None));
  CHECK(!A.sp->handle(PairButton::Short));           // not pairing: the press is the application's
  CHECK(A.sp->handle(PairButton::Long));             // within the window: starts a pairing
  CHECK(A.sp->busy());
  CHECK(A.sp->handle(PairButton::None));             // busy: the application skips its loop
  std::thread tb([&] { B.sp->pair(nullptr); });
  while (!A.ui.waitingConfirm || !B.ui.waitingConfirm) MemTransport::sleepMs(2);
  CHECK(A.sp->handle(PairButton::Short));            // confirms
  B.sp->confirm();
  tb.join();
  while (A.sp->busy()) MemTransport::sleepMs(2);
  CHECK(A.sp->lastResult() == PairResult::Ok);
  CHECK(radio.pauses == 1 && radio.resumes == 1);
  CHECK(stable(A, B));

  A.sp->closeRepairWindow();
  CHECK(!A.sp->handle(PairButton::Long));            // window closed: nothing
}

// A user with a button: held as the board starts or not, and pressing to
// confirm as soon as the board asks.
struct BootButton : PairInput {
  FakeUi &ui;
  bool held;
  BootButton(FakeUi &u, bool h) : ui(u), held(h) {}
  PairButton read() override { return ui.waitingConfirm ? PairButton::Short : PairButton::None; }
  bool heldAtStart() override { return held; }
};

static void testBootPairing() {
  printf("provision(): first start, button held at start\n");
  Channel ch;
  Node A, B;
  A.cfg.rendezvousMs = B.cfg.rendezvousMs = 600;
  CHECK(A.boot(ch, 0) && B.boot(ch, 1));

  // First start with the button held on both boards: they pair at once.
  {
    BootButton ia(A.ui, true), ib(B.ui, true);
    PairResult rb = PairResult::Busy;
    std::thread tb([&] { rb = B.sp->provision(ib); });
    const PairResult ra = A.sp->provision(ia);
    tb.join();
    CHECK(ra == PairResult::Ok && rb == PairResult::Ok && stable(A, B));
  }
  PeerRecord before, after;
  CHECK(A.record(B.sp->localId(), before));

  // A later start without the button: nothing to do, no waiting.
  CHECK(A.boot(ch, 0) && B.boot(ch, 1));
  {
    BootButton ia(A.ui, false);
    const uint64_t t0 = nowUs();
    CHECK(A.sp->provision(ia) == PairResult::Ok && nowUs() - t0 < 50000);
    CHECK(A.record(B.sp->localId(), after) && memcmp(before.key, after.key, 32) == 0);
  }

  // Held at start on both: a new key for the board already known.
  {
    A.ui.reset();
    B.ui.reset();
    BootButton ia(A.ui, true), ib(B.ui, true);
    PairResult rb = PairResult::Busy;
    std::thread tb([&] { rb = B.sp->provision(ib); });
    const PairResult ra = A.sp->provision(ia);
    tb.join();
    CHECK(ra == PairResult::Ok && rb == PairResult::Ok && stable(A, B));
    CHECK(A.record(B.sp->localId(), after) && memcmp(before.key, after.key, 32) != 0);
    CHECK(A.sp->peerCount() == 1 && B.sp->peerCount() == 1);
  }

  // Held on one board only: nobody answers, and it goes on with its pairing.
  CHECK(A.boot(ch, 0));
  {
    A.ui.reset();
    BootButton ia(A.ui, true);
    CHECK(A.sp->provision(ia) == PairResult::NoPeer);
    CHECK(A.record(B.sp->localId(), before) && memcmp(before.key, after.key, 32) == 0);
  }
}

// Button timing (ButtonInput): each press timed from its own edges.
static void testPressDecoder() {
  printf("button presses\n");
  PressDecoder d(1000);
  d.start(false, 0);
  // A short press, read late.
  d.edge(true, 100);
  d.edge(false, 300);
  CHECK(d.read(false, 5000) == PairButton::Short && d.read(false, 5001) == PairButton::None);
  // A hold that ended before anybody read: still Long, never Short.
  d.edge(true, 6000);
  d.edge(false, 8100);
  CHECK(d.read(false, 9000) == PairButton::Long);
  // Long while still held, then nothing at release.
  d.edge(true, 10000);
  CHECK(d.read(true, 10500) == PairButton::None && d.read(true, 11000) == PairButton::Long);
  d.edge(false, 11500);
  CHECK(d.read(false, 11600) == PairButton::None);
  // Contact bounce: edges closer than 20 ms do not count.
  d.edge(true, 12000);
  d.edge(false, 12005);
  d.edge(true, 12010);
  d.edge(false, 12200);
  CHECK(d.read(false, 12300) == PairButton::Short);
  // A release lost in the bounce: the level settles it.
  d.edge(true, 13000);
  d.edge(false, 13010);
  CHECK(d.read(false, 13100) == PairButton::None && d.read(false, 13200) == PairButton::Short);
  // Two presses between reads: the Long one wins.
  d.edge(true, 14000);
  d.edge(false, 15500);
  d.edge(true, 16000);
  d.edge(false, 16100);
  CHECK(d.read(false, 17000) == PairButton::Long && d.read(false, 17001) == PairButton::None);
  // clear(): pending presses go; one still held may end Long, never Short.
  d.edge(true, 18000);
  d.edge(false, 18100);
  d.edge(true, 18200);
  d.clear();
  d.edge(false, 18300);
  CHECK(d.read(false, 18400) == PairButton::None);
  d.edge(true, 19000);
  d.clear();
  CHECK(d.read(true, 20100) == PairButton::Long);
  // A Short not read yet, then a press still going on: the Short waits, and
  // gives way if that press becomes Long (a rejection right after a
  // confirmation)...
  PressDecoder q(1000);
  q.start(false, 0);
  q.edge(true, 100);
  q.edge(false, 300);
  q.edge(true, 400);
  CHECK(q.read(true, 900) == PairButton::None);
  CHECK(q.read(true, 1500) == PairButton::Long && q.read(true, 1600) == PairButton::None);
  q.edge(false, 1700);
  CHECK(q.read(false, 1800) == PairButton::None);
  // ...or comes out when that press ends short.
  q.edge(true, 2000);
  q.edge(false, 2200);
  q.edge(true, 2300);
  CHECK(q.read(true, 2400) == PairButton::None);
  q.edge(false, 2500);
  CHECK(q.read(false, 2600) == PairButton::Short && q.read(false, 2700) == PairButton::None);
  // Held when reading starts: no press at all, then presses as usual.
  PressDecoder h(1000);
  h.start(true, 0);
  CHECK(h.read(true, 3000) == PairButton::None);
  h.edge(false, 3500);
  CHECK(h.read(false, 3600) == PairButton::None);
  h.edge(true, 4000);
  h.edge(false, 4100);
  CHECK(h.read(false, 4200) == PairButton::Short);
}

// A button pressed while the code is shown: the press waits in the input
// until somebody reads it, as in ButtonInput.
struct EarlyPress : PairInput {
  std::atomic<PairButton> pending{PairButton::None};
  std::atomic<int> clears{0};
  PairButton read() override { return pending.exchange(PairButton::None); }
  void clear() override {
    pending = PairButton::None;
    ++clears;
  }
};

static void testPressDuringCode() {
  printf("presses during the code\n");
  for (const PairButton kind : {PairButton::Short, PairButton::Long}) {
    Channel ch;
    Node A, B;
    A.cfg.confirmMs = B.cfg.confirmMs = 1000;
    A.cfg.codeMs = B.cfg.codeMs = 300;
    CHECK(A.boot(ch, 0) && B.boot(ch, 1));
    EarlyPress early;
    PairResult ra = PairResult::Busy, rb = PairResult::Busy;
    std::atomic<bool> doneB{false};
    std::thread ta([&] { ra = A.sp->pair(&early); });
    std::thread tb([&] {
      rb = B.sp->pair(nullptr);
      doneB = true;
    });
    while (!A.ui.sasShown) MemTransport::sleepMs(1);
    MemTransport::sleepMs(A.cfg.codeLeadMs + 50);
    early.pending = kind;   // halfway through the code
    while (!doneB && !B.ui.waitingConfirm) MemTransport::sleepMs(2);
    B.sp->confirm();        // B confirms as it should
    ta.join();
    tb.join();
    CHECK(early.clears == 1);
    if (kind == PairButton::Short) {
      // Not a confirmation: nobody confirms on A, nothing is saved.
      CHECK(ra == PairResult::Timeout && rb == PairResult::Timeout);
      CHECK(!A.sp->hasPeer() && !B.sp->hasPeer());
    } else {
      // A rejection counts as soon as the code ends.
      CHECK(ra == PairResult::Rejected && rb == PairResult::Rejected);
    }
  }
}

// ButtonInput on the PC: the real decoder, fed with edges by the test.
struct DecodedButton : PairInput {
  std::mutex m;
  PressDecoder decoder{1000};
  bool down = false;
  DecodedButton() { decoder.start(false, ms()); }
  static uint32_t ms() { return (uint32_t)(nowUs() / 1000); }
  void set(bool on) {
    std::lock_guard<std::mutex> l(m);
    down = on;
    decoder.edge(on, ms());
  }
  PairButton read() override {
    std::lock_guard<std::mutex> l(m);
    return decoder.read(down, ms());
  }
  void clear() override {
    std::lock_guard<std::mutex> l(m);
    decoder.clear();
  }
};

// A slow medium: taking in the peer's CONFIRM keeps the board busy for 1.5 s.
// Meanwhile the user confirms, then changes their mind and holds to reject.
class BusyOnConfirm : public MemTransport {
 public:
  BusyOnConfirm(Channel &ch, int side, DecodedButton &button)
      : MemTransport(ch, side), button_(button) {}
  int receive(uint8_t *buf, size_t cap, uint32_t timeoutMs, SyncMark *mark) override {
    const int n = MemTransport::receive(buf, cap, timeoutMs, mark);
    if (!done_ && n >= 2 && buf[0] == kProtocolVersion && buf[1] == proto::kConfirm) {
      done_ = true;
      button_.set(true);
      sleepMs(100);
      button_.set(false);   // a short press: confirm
      sleepMs(100);
      button_.set(true);    // held, and still held: reject
      sleepMs(1300);
    }
    return n;
  }

 private:
  DecodedButton &button_;
  bool done_ = false;
};

static void testRejectAfterConfirm() {
  printf("a rejection right after a confirmation\n");
  Channel ch;
  Node A, B;
  DecodedButton button;
  A.tr.reset(new BusyOnConfirm(ch, 0, button));
  A.sp.reset(new SecurePair(*A.tr, *A.store, A.ui, A.ui));
  CHECK(A.sp->begin(A.cfg) && B.boot(ch, 1));
  PairResult ra = PairResult::Busy, rb = PairResult::Busy;
  std::atomic<bool> doneB{false};
  std::thread tb([&] {
    rb = B.sp->pair(nullptr);
    doneB = true;
  });
  std::thread user([&] {
    while (!doneB && !B.ui.waitingConfirm) MemTransport::sleepMs(2);
    B.sp->confirm();
  });
  ra = A.sp->pair(&button);
  tb.join();
  user.join();
  button.set(false);
  CHECK(ra == PairResult::Rejected && rb == PairResult::Rejected);
  CHECK(!A.sp->hasPeer() && !B.sp->hasPeer());
}

// --- Storage ----------------------------------------------------------------------

// A DeviceKey for the tests: HMAC under a secret the test chooses.
struct FakeChipKey : DeviceKey {
  uint8_t secret[32];
  bool present = true;

  explicit FakeChipKey(uint8_t seed) { memset(secret, seed, sizeof(secret)); }

  bool available() override { return present; }

  bool derive(const void *message, size_t len, uint8_t out[32]) override {
    if (!present) return false;
    crypto::hmacSha256(secret, sizeof(secret), message, len, out);
    return true;
  }
};

static bool contains(const std::vector<uint8_t> &data, const uint8_t *part, size_t n) {
  return std::search(data.begin(), data.end(), part, part + n) != data.end();
}

static PeerRecord samplePeer(uint8_t seed) {
  PeerRecord r;
  uint8_t *p = reinterpret_cast<uint8_t *>(&r);
  for (size_t i = 0; i < sizeof(r); ++i) p[i] = (uint8_t)(seed + i * 13);
  r.format = 1;
  r.flags = 0;
  return r;
}

static void testSeal() {
  printf("sealed records\n");
  uint8_t secret[32];
  memset(secret, 1, sizeof(secret));
  seal::Keys k, other;
  seal::deriveKeys(secret, k);
  secret[0] ^= 1;
  seal::deriveKeys(secret, other);

  const uint8_t ctx[] = {'n', 's', 0, 'p', '0', '0', 0};
  const uint8_t ctx2[] = {'n', 's', 0, 'p', '0', '1', 0};
  uint8_t rec[100], out[100];
  for (size_t i = 0; i < sizeof(rec); ++i) rec[i] = (uint8_t)(i * 7 + 3);
  std::vector<uint8_t> blob(sizeof(rec) + seal::kOverhead), blob2(blob.size());

  CHECK(seal::seal(k, ctx, sizeof(ctx), rec, sizeof(rec), blob.data()));
  CHECK(seal::open(k, ctx, sizeof(ctx), blob.data(), blob.size(), out, sizeof(out)) &&
        memcmp(out, rec, sizeof(rec)) == 0);
  CHECK(!contains(blob, rec, 8));                    // nothing in clear
  CHECK(seal::seal(k, ctx, sizeof(ctx), rec, sizeof(rec), blob2.data()));
  CHECK(blob != blob2);                              // a new nonce every time

  CHECK(!seal::open(other, ctx, sizeof(ctx), blob.data(), blob.size(), out, sizeof(out)));
  CHECK(!seal::open(k, ctx2, sizeof(ctx2), blob.data(), blob.size(), out, sizeof(out)));
  CHECK(!seal::open(k, ctx, sizeof(ctx), blob.data(), blob.size() - 1, out, sizeof(out) - 1));
  int opened = 0;
  for (size_t i = 0; i < blob.size(); ++i) {
    blob[i] ^= 0x01;
    opened += seal::open(k, ctx, sizeof(ctx), blob.data(), blob.size(), out, sizeof(out));
    blob[i] ^= 0x01;
  }
  CHECK(opened == 0);                                // every changed byte is caught
  const uint8_t zero[sizeof(out)] = {};
  CHECK(memcmp(out, zero, sizeof(out)) == 0);        // and leaves nothing behind
}

static void testSealedStorage() {
  printf("NVS storage, sealed\n");
  FakeChipKey chip(1), otherChip(2);
  IdentityRecord id, id2, got;
  CHECK(crypto::x25519Keypair(id.priv, id.pub) && crypto::x25519Keypair(id2.priv, id2.pub));
  const PeerRecord p0 = samplePeer(0x10), p1 = samplePeer(0x20);
  PeerRecord r;
  uint32_t epoch = 0;

  NvsPairStorage st(chip, Encryption::IfAvailable, "t-enc");
  CHECK(st.begin() && st.encrypted() && !st.loadIdentity(got));
  CHECK(!st.nextEpoch(epoch) && !st.savePeer(0, p0));   // nothing before the identity
  CHECK(st.saveIdentity(id));
  CHECK(st.nextEpoch(epoch) && epoch == 1);
  CHECK(st.nextEpoch(epoch) && epoch == 2);
  CHECK(st.savePeer(0, p0) && st.savePeer(1, p1));

  Preferences::Namespace &flash = Preferences::flash()["t-enc"];
  bool hidden = flash.size() == 3;                   // "sid" (with the epoch), "s00", "s01"
  for (const auto &rec : flash)
    hidden = hidden && !contains(rec.second, id.priv, 8) && !contains(rec.second, id.pub, 8) &&
             !contains(rec.second, p0.key, 8) && !contains(rec.second, p1.key, 8);
  CHECK(hidden);

  // After a reset: the same identity, the next epoch, the same peers.
  {
    NvsPairStorage again(chip, Encryption::IfAvailable, "t-enc");
    CHECK(again.begin() && again.loadIdentity(got) && memcmp(&got, &id, sizeof(id)) == 0);
    CHECK(again.nextEpoch(epoch) && epoch == 3);
    CHECK(again.loadPeer(0, r) && memcmp(&r, &p0, sizeof(r)) == 0);
    CHECK(again.loadPeer(1, r) && memcmp(&r, &p1, sizeof(r)) == 0);
    CHECK(!again.loadPeer(2, r));
  }

  // Two peer records swapped: neither opens.
  std::swap(flash["s00"], flash["s01"]);
  {
    NvsPairStorage again(chip, Encryption::IfAvailable, "t-enc");
    CHECK(again.begin() && !again.loadPeer(0, r) && !again.loadPeer(1, r));
  }
  std::swap(flash["s00"], flash["s01"]);

  // The same flash on another chip, or moved to another namespace: refused,
  // and never read in clear instead.
  {
    NvsPairStorage clone(otherChip, Encryption::IfAvailable, "t-enc");
    CHECK(!clone.begin() && clone.encrypted() && !clone.saveIdentity(id));
  }
  Preferences::flash()["t-moved"] = flash;
  {
    NvsPairStorage moved(chip, Encryption::IfAvailable, "t-moved");
    CHECK(!moved.begin());
  }

  // A damaged identity stops begin(), and nothing is written over it.
  flash["sid"][20] ^= 1;
  {
    NvsPairStorage again(chip, Encryption::IfAvailable, "t-enc");
    CHECK(!again.begin() && again.encrypted() && !again.saveIdentity(id2));
    CHECK(flash.size() == 3);
  }
  flash["sid"][20] ^= 1;

  // Without its identity the board starts over. The old peer records no
  // longer open, so the epoch that starts again from 1 only meets new keys.
  flash.erase("sid");
  {
    NvsPairStorage again(chip, Encryption::IfAvailable, "t-enc");
    CHECK(again.begin() && !again.loadIdentity(got));
    CHECK(again.saveIdentity(id2) && again.nextEpoch(epoch) && epoch == 1);
    CHECK(!again.loadPeer(0, r) && !again.loadPeer(1, r));
    CHECK(again.savePeer(0, p1) && again.loadPeer(0, r) && memcmp(&r, &p1, sizeof(r)) == 0);
    CHECK(again.erasePeer(0) && !again.loadPeer(0, r));
    CHECK(again.saveIdentity(id) && again.nextEpoch(epoch) && epoch == 2);   // epoch kept
    CHECK(again.factoryReset() && flash.empty());
  }
}

static void testStorageModes() {
  printf("NVS storage, in clear until the chip has its key\n");
  FakeChipKey chip(5), noKey(6);
  chip.present = false;                              // its key is not written yet
  noKey.present = false;
  IdentityRecord id, planted, got;
  CHECK(crypto::x25519Keypair(id.priv, id.pub) &&
        crypto::x25519Keypair(planted.priv, planted.pub));
  const PeerRecord p0 = samplePeer(0x50);
  PeerRecord r;
  uint32_t epoch = 0;
  Preferences::Namespace &flash = Preferences::flash()["t-modes"];

  // No key: nothing at all with Encryption::Required, in clear otherwise.
  {
    NvsPairStorage required(chip, Encryption::Required, "t-modes");
    CHECK(!required.begin() && !required.encrypted() && !required.saveIdentity(id));
    CHECK(flash.empty());
  }
  {
    NvsPairStorage st(chip, Encryption::IfAvailable, "t-modes");
    CHECK(st.begin() && !st.encrypted());
    CHECK(st.saveIdentity(id) && st.nextEpoch(epoch) && st.savePeer(0, p0));
    CHECK(flash.count("id") == 1 && flash.count("epoch") == 1 && flash.count("p00") == 1);
    CHECK(contains(flash["id"], id.priv, 8));        // really in clear
  }

  // The key is written: from the next start the records are sealed, and those
  // in clear are erased, not imported. The board starts over.
  chip.present = true;
  {
    NvsPairStorage st(chip, Encryption::Required, "t-modes");
    CHECK(st.begin() && st.encrypted() && flash.empty());
    CHECK(!st.loadIdentity(got) && !st.loadPeer(0, r));
    CHECK(st.saveIdentity(id) && st.nextEpoch(epoch) && epoch == 1);
  }

  // Records planted in clear next to the sealed ones are never read.
  {
    NvsPairStorage planter(noKey, Encryption::IfAvailable, "t-modes");
    CHECK(planter.begin() && !planter.encrypted());
    CHECK(planter.saveIdentity(planted) && planter.savePeer(0, p0));
  }
  {
    NvsPairStorage st(chip, Encryption::IfAvailable, "t-modes");
    CHECK(st.begin() && st.loadIdentity(got) && memcmp(&got, &id, sizeof(id)) == 0);
    CHECK(!st.loadPeer(0, r) && flash.count("id") == 0 && flash.count("p00") == 0);
    CHECK(st.factoryReset() && flash.empty());
  }

  // Without a DeviceKey, the chip's own key is used; on the PC there is none.
  {
    NvsPairStorage plain(Encryption::IfAvailable, "t-modes");
    NvsPairStorage required(Encryption::Required, "t-modes");
    CHECK(plain.begin() && !plain.encrypted() && !required.begin());
  }
}

static void testSealedPairing() {
  printf("pairing with sealed storage\n");
  Channel ch;
  FakeChipKey chip(7);
  NvsPairStorage sealed(chip, Encryption::Required, "t-pair");
  Node A, B;
  A.store = &sealed;
  CHECK(A.boot(ch, 0) && B.boot(ch, 1) && sealed.encrypted());
  const Outcome o = runPair(A, B, Plan());
  CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok && stable(A, B));

  // A restarts: identity, peer and key come back from the sealed records.
  const PeerId idA = A.sp->localId(), idB = B.sp->localId();
  const uint32_t epoch = A.sp->epoch();
  CHECK(A.boot(ch, 0));
  CHECK(A.sp->localId() == idA && A.sp->epoch() == epoch + 1 && A.sp->hasPeer());
  SecureLink la(*A.sp), lb(*B.sp);
  uint8_t buf[16];
  PeerId from = {};
  CHECK(la.send(idB, "sealed") == SecureLink::SendResult::Ok);
  CHECK(lb.receive(buf, sizeof(buf), from, 100) == 6 && memcmp(buf, "sealed", 6) == 0 &&
        from == idA);
}

static void testNvsStorage() {
  printf("NVS storage, in clear\n");
  IdentityRecord id, got;
  CHECK(crypto::x25519Keypair(id.priv, id.pub));
  const PeerRecord p0 = samplePeer(0x30), p9 = samplePeer(0x40);
  PeerRecord r;
  uint32_t epoch = 0;
  Preferences::Namespace &flash = Preferences::flash()["t-nvs"];

  {
    NvsPairStorage st(Encryption::IfAvailable, "t-nvs");
    CHECK(st.begin() && !st.encrypted() && !st.loadIdentity(got) && st.saveIdentity(id));
    CHECK(st.nextEpoch(epoch) && epoch == 1);
    CHECK(st.savePeer(0, p0) && st.nextEpoch(epoch) && epoch == 2);
    CHECK(!st.savePeer(9, p9));                      // beyond its 8 slots
  }
  {
    NvsPairStorage wide(Encryption::IfAvailable, "t-nvs", 16);   // the same flash, 16 slots
    CHECK(wide.begin() && wide.savePeer(9, p9));
  }

  // After a reset: the same identity, the next epoch, the same peer.
  {
    NvsPairStorage st(Encryption::IfAvailable, "t-nvs");
    CHECK(st.begin() && st.loadIdentity(got) && memcmp(&got, &id, sizeof(id)) == 0);
    CHECK(st.nextEpoch(epoch) && epoch == 3);
    CHECK(st.loadPeer(0, r) && memcmp(&r, &p0, sizeof(r)) == 0);
    flash["p00"][10] ^= 1;
    CHECK(!st.loadPeer(0, r));                       // the CRC catches the damage
    flash["p00"][10] ^= 1;
  }

  // The epoch is lost with peers saved: the peers go too, from every slot,
  // before the epoch starts again. The identity stays.
  flash.erase("epoch");
  {
    NvsPairStorage st(Encryption::IfAvailable, "t-nvs");
    CHECK(st.begin() && st.loadIdentity(got) && memcmp(&got, &id, sizeof(id)) == 0);
    CHECK(st.nextEpoch(epoch) && epoch == 1);
    CHECK(!st.loadPeer(0, r) && flash.count("p00") == 0 && flash.count("p09") == 0);
    CHECK(st.factoryReset() && flash.empty());
  }

  // The same through SecurePair: the board comes back unpaired, and pairing
  // again replaces its old record on the other board. Messages flow again at
  // once, although A's epochs start over from 1.
  Channel ch;
  NvsPairStorage nvs(Encryption::IfAvailable, "t-nvs-pair");
  Node A, B;
  A.store = &nvs;
  CHECK(A.boot(ch, 0) && B.boot(ch, 1));
  CHECK(runPair(A, B, Plan()).a == PairResult::Ok);
  const PeerId idA = A.sp->localId(), idB = B.sp->localId();
  uint8_t buf[16];
  PeerId from = {};
  std::vector<uint8_t> oldFrame;
  ch.filter = [&](int side, std::vector<uint8_t> &m) {
    if (side == 0 && m[0] == SecureLink::kTypeData) oldFrame = m;
    return false;
  };
  for (int i = 0; i < 2; ++i) {   // A restarts and talks: B saves each epoch
    CHECK(A.boot(ch, 0));
    SecureLink la(*A.sp), lb(*B.sp);
    CHECK(la.send(idB, "hi") == SecureLink::SendResult::Ok && lb.receive(buf, sizeof(buf), from, 100) == 2);
  }
  ch.filter = nullptr;
  PeerRecord rb;
  CHECK(A.sp->epoch() == 3 && B.record(idA, rb) && rb.rxEpoch == 3);
  Preferences::flash()["t-nvs-pair"].erase("epoch");
  CHECK(A.boot(ch, 0) && !A.sp->hasPeer() && A.sp->epoch() == 1);
  const Outcome o = runPair(A, B, Plan());
  CHECK(o.a == PairResult::Ok && o.b == PairResult::Ok && stable(A, B));
  CHECK(A.sp->peerCount() == 1 && B.sp->peerCount() == 1);
  SecureLink la(*A.sp), lb(*B.sp);
  CHECK(la.send(idB, "back") == SecureLink::SendResult::Ok && lb.receive(buf, sizeof(buf), from, 100) == 4);
  CHECK(lb.send(idA, "ok") == SecureLink::SendResult::Ok && la.receive(buf, sizeof(buf), from, 100) == 2);
  // The old key is gone: a frame recorded before is refused.
  inject(ch, 1, oldFrame);
  CHECK(lb.receive(buf, sizeof(buf), from, 100) == 0 && lb.stats().unknownKey == 1);
}

int main(int argc, char **argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  if (argc > 1 && argv[1][0] == 's') {
    testSecureLink();
    testReplayEdges();
    testRepairCutTwice();
    testRepairPeerBehind();
    testDropOldKey();
    testPeerTable();
    testSecondTransport();
    testDatagram();
    printf("%d checks, %d failures\n", checks, failures);
    return failures;
  }
  if (argc > 1 && argv[1][0] == 'f') {
    for (int i = 0; i < 15; ++i) testMultiPeerAndFull();
    printf("%d checks, %d failures\n", checks, failures);
    return failures;
  }
  if (argc > 1 && argv[1][0] == 'e') {
    testSeal();
    testSealedStorage();
    testStorageModes();
    testSealedPairing();
    testNvsStorage();
    printf("%d checks, %d failures\n", checks, failures);
    return failures;
  }
  if (argc > 1) {
    testCrypto();
    testKeySchedule();
    printf("%d checks, %d failures\n", checks, failures);
    return failures;
  }
  testCrypto();
  testKeySchedule();
  testSeal();
  testSealedStorage();
  testStorageModes();
  testFirstPairAndRepair();
  testNotConfirmed();
  testTamper();
  testLostDone();
  testMultiPeerAndFull();
  testStorageFailure();
  testSealedPairing();
  testNvsStorage();
  testNonBlocking();
  testHandle();
  testBootPairing();
  testPressDecoder();
  testPressDuringCode();
  testRejectAfterConfirm();
  testSecureLink();
  testReplayEdges();
  testRepairCutTwice();
  testRepairPeerBehind();
  testDropOldKey();
  testPeerTable();
  testSecondTransport();
  testDatagram();
  testLossy();
  printf("\n%d checks, %d failures\n", checks, failures);
  (void)hex;
  return failures ? 1 : 0;
}
