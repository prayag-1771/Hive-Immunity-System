// Hive immune node for ESP32 (Arduino core 3.x).
//
// Same logic as agent/hive_core.py, step for step: 1-second feature windows, a learned
// baseline (kept in NVS so a reboot skips learning), anomaly score, quarantine, block
// list, and the signed-vaccine pipeline (size -> schema -> issuer -> replay -> HMAC ->
// rate limit -> protected target -> quorum). Talks plain JSON over Wi-Fi UDP.
//
// It is also a Bluetooth hub (HIVE_BLE): Bluetooth devices that cannot run Hive connect
// to it, and one that starts misbehaving is cut off and refused (ble_hub.h).
//
// Onboard LED: slow blink = learning, solid/off = healthy (follows the hub's
// light_on/light_off), fast blink = quarantined, short flash every 2 s = no Wi-Fi.
// Serial (115200): prints events; type  s = status, r = relearn, x = reset.
//
// Setup: python tools/provision_keys.py --ssid <SSID> --password <PASS>  (writes secrets.h)

#define ARDUINOJSON_USE_LONG_LONG 1
#include <Arduino.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <math.h>

#include "hive_sign.h"
#include "model.h"
#ifdef HIVE_HOST_TEST
#include "test_secrets.h"  // firmware/test: fixed keys for the PC harness
#else
#include "secrets.h"
#endif

#ifndef HIVE_BLE
#define HIVE_BLE 0
#endif
#ifndef BLE_HUB_NAME
#define BLE_HUB_NAME "Hive-" NODE_ID
#endif
#if HIVE_BLE
#include "ble_hub.h"  // needs PartitionScheme=huge_app: Bluetooth + Wi-Fi exceed 1.3 MB
#endif

// ------------------------------------------------------------------ limits (= hive_core)
static const int MAX_MSG = 512;
static const int MAX_VAX = 300;
static const int MAX_TTL = 600;
static const int NF = 5;
static const float STD_FLOOR[NF] = {1.0f, 0.5f, 0.05f, 0.05f, 5.0f};
static const int MAX_SENDERS = 16;
static const int MAX_KNOWN = 8;
static const int MAX_BLOCKS = 8;
static const int MAX_PENDING = 8;
static const int MAX_ISSUERS = 12;
static const int RATE_SLOTS = VAX_RATE_MAX_PER_MIN + 1;
static const uint32_t BASELINE_MAGIC = 0x48495631;  // "HIV1"

#if HAVE_AE_MODEL
static const float DET_THRESHOLD = AE_THRESHOLD;
static const char* DET_NAME = "autoencoder";
static const int MODEL_BYTES = 4 * (NF * AE_HIDDEN + AE_HIDDEN + AE_HIDDEN * NF + NF);
#else
static const float DET_THRESHOLD = THRESHOLD;
static const char* DET_NAME = "zscore";
static const int MODEL_BYTES = NF * 2 * 4;
#endif

enum State { LEARNING, HEALTHY, QUARANTINED };
static const char* STATE_NAMES[] = {"learning", "healthy", "quarantined"};

struct Baseline {
  uint32_t magic;
  uint32_t n;
  float mean[NF];
  float m2[NF];
  uint32_t nknown;
  uint32_t known[MAX_KNOWN];
};

struct Sender {
  uint32_t ip;
  uint16_t n;
};

struct Window {
  uint16_t count, unknown, malformed, distinct;
  uint32_t bytes;
  uint8_t nsenders;
  Sender s[MAX_SENDERS];
};

struct Block {
  bool used, logged;
  uint32_t ip, until;
};

struct Pending {
  bool used;
  uint32_t target;
  uint32_t vote[MAX_ISSUERS];  // millis() of each issuer's vote, 0 = none
};

struct Issuer {
  const char* id;
  uint8_t key[hive::KEY_LEN];
  bool hasSeq;
  uint32_t lastSeq;
  char lastCanon[200];
  char lastSig[hive::SIG_HEX_LEN + 1];
  uint32_t times[RATE_SLOTS];
  uint8_t ntimes;
  bool distrusted;
  uint32_t distrustUntil;
};

// ------------------------------------------------------------------ state
static WiFiUDP dataUdp, vaxUdp;
static Preferences prefs;
static uint8_t myKey[hive::KEY_LEN], adminKey[hive::KEY_LEN];
static Issuer issuers[MAX_ISSUERS];
static int nIssuers = 0;

static State state = LEARNING;
static Baseline baseline, learnBase;
static bool haveBaseline = false;
static uint32_t learnStart = 0;  // 0 = waiting for the hub
static uint32_t hubIp = 0, dashIp = 0, myIp = 0;
static Window win;
static uint32_t winStart = 0;
static float features[NF] = {0};
static float score = 0;
static int hot = 0;
static uint32_t calmSince = 0;
static bool calm = false;
static bool light = false;

static Block blocks[MAX_BLOCKS];
static Pending pending[MAX_PENDING];
static uint32_t vaxSeq = 0;
static bool hasCtrlSeq = false;
static uint64_t lastCtrlSeq = 0;
static uint32_t cBlocked = 0, cDropped = 0, cIssued = 0, cAdopted = 0, cRejected = 0;
static uint32_t nextStatus = 0, lastWifiTry = 0;

static char rxBuf[MAX_MSG + 1];

#if HIVE_BLE
static hive::BleWatch ble(LEARN_SECONDS * 1000UL, WINDOW_MS, THRESHOLD, CONSECUTIVE);
#endif

// ------------------------------------------------------------------ helpers
static inline bool reached(uint32_t now, uint32_t t) { return (int32_t)(now - t) >= 0; }

static void ipText(uint32_t ip, char out[16]) { hive::formatIPv4(ip, out); }

static void ledWrite(bool on) { digitalWrite(LED_PIN, (on ^ (LED_ACTIVE_LOW != 0)) ? HIGH : LOW); }

static void sendTo(WiFiUDP& udp, uint32_t ip, uint16_t port, const char* data, size_t len) {
  if (!ip) return;
  udp.beginPacket(IPAddress(ip), port);
  udp.write((const uint8_t*)data, len);
  udp.endPacket();
}

static uint32_t subnetBroadcast() {
  uint32_t mask = (uint32_t)WiFi.subnetMask();
  return myIp ? (myIp | ~mask) : 0;
}

static int broadcastTargets(uint32_t out[2]) {
  int n = 0;
  uint32_t a = 0, b = subnetBroadcast();
  hive::parseIPv4(BROADCAST_IP, &a);
  if (a) out[n++] = a;
  if (b && b != a) out[n++] = b;
  return n;
}

static int statusTargets(uint32_t out[2]) {
  uint32_t d = dashIp ? dashIp : hubIp;
  if (d) {
    out[0] = d;
    return 1;
  }
  return broadcastTargets(out);
}

static void sendStatusJson(const char* data, size_t len) {
  uint32_t t[2];
  int n = statusTargets(t);
  for (int i = 0; i < n; i++) sendTo(vaxUdp, t[i], STATUS_PORT, data, len);
}

static void event(const char* kind, const char* detail, uint32_t target = 0) {
  Serial.printf("[%s] %s: %s\n", NODE_ID, kind, detail);
  JsonDocument doc;
  doc["v"] = 1;
  doc["t"] = "event";
  doc["node"] = NODE_ID;
  doc["kind"] = kind;
  doc["detail"] = detail;
  if (target) {
    char ip[16];
    ipText(target, ip);
    doc["target"] = ip;
  }
  char out[400];
  size_t len = serializeJson(doc, out, sizeof out);
  sendStatusJson(out, len);
}

static void reject(const char* reason, const char* detail) {
  cRejected++;
  char msg[160];
  snprintf(msg, sizeof msg, "%s: %s", reason, detail);
  event("vax_rejected", msg);
}

// ------------------------------------------------------------------ persistence
static void saveBaseline() {
  if (haveBaseline) prefs.putBytes("base", &baseline, sizeof baseline);
  else prefs.remove("base");
}

static void loadPersisted() {
  vaxSeq = prefs.getUInt("seq", 0);
  Baseline b;
  if (prefs.isKey("base") && prefs.getBytes("base", &b, sizeof b) == sizeof b && b.magic == BASELINE_MAGIC &&
      b.n >= 3) {
    baseline = b;
    haveBaseline = true;
    state = HEALTHY;
  }
}

// ------------------------------------------------------------------ baseline / scoring
static void baseAdd(Baseline& b, const float f[NF]) {
  b.n++;
  for (int i = 0; i < NF; i++) {
    float d = f[i] - b.mean[i];
    b.mean[i] += d / b.n;
    b.m2[i] += d * (f[i] - b.mean[i]);
  }
}

static void baseZ(const Baseline& b, const float f[NF], float z[NF]) {
  for (int i = 0; i < NF; i++) {
    float sd = b.n > 1 ? sqrtf(b.m2[i] / (b.n - 1)) : 0.0f;
    if (sd < STD_FLOOR[i]) sd = STD_FLOOR[i];
    z[i] = (f[i] - b.mean[i]) / sd;
  }
}

static bool baseKnows(const Baseline& b, uint32_t ip) {
  for (uint32_t i = 0; i < b.nknown; i++)
    if (b.known[i] == ip) return true;
  return false;
}

static void baseRemember(Baseline& b, uint32_t ip) {
  if (!baseKnows(b, ip) && b.nknown < (uint32_t)MAX_KNOWN) b.known[b.nknown++] = ip;
}

static float detectorScore(const float f[NF]) {
  float z[NF];
  baseZ(baseline, f, z);
#if HAVE_AE_MODEL
  float x[NF], h[AE_HIDDEN], err = 0;
  for (int i = 0; i < NF; i++) x[i] = fmaxf(-AE_CLIP, fminf(AE_CLIP, z[i]));
  for (int j = 0; j < AE_HIDDEN; j++) {
    float a = AE_B1[j];
    for (int i = 0; i < NF; i++) a += x[i] * AE_W1[i][j];
    h[j] = tanhf(a);
  }
  for (int k = 0; k < NF; k++) {
    float y = AE_B2[k];
    for (int j = 0; j < AE_HIDDEN; j++) y += h[j] * AE_W2[j][k];
    err += (x[k] - y) * (x[k] - y);
  }
  return sqrtf(err / NF);
#else
  float m = 0;
  for (int i = 0; i < NF; i++) m = fmaxf(m, fabsf(z[i]));
  return m;
#endif
}

// ------------------------------------------------------------------ block list / pending
static Block* findBlock(uint32_t ip, uint32_t now) {
  for (auto& b : blocks)
    if (b.used && b.ip == ip && !reached(now, b.until)) return &b;
  return nullptr;
}

static void dropPending(uint32_t target) {
  for (auto& p : pending)
    if (p.used && p.target == target) p.used = false;
}

static void addBlock(uint32_t ip, uint32_t ttlS, uint32_t now) {
  uint32_t until = now + ttlS * 1000UL;
  Block* slot = nullptr;
  for (auto& b : blocks)
    if (b.used && b.ip == ip) slot = &b;
  if (!slot)
    for (auto& b : blocks)
      if (!b.used) { slot = &b; break; }
  if (!slot) {  // full: replace the one expiring soonest
    slot = &blocks[0];
    for (auto& b : blocks)
      if ((int32_t)(b.until - slot->until) < 0) slot = &b;
  }
  if (!slot->used || slot->ip != ip || (int32_t)(until - slot->until) > 0) slot->until = until;
  slot->used = true;
  slot->ip = ip;
  slot->logged = false;
  dropPending(ip);
}

static bool isProtected(uint32_t ip) { return ip == hubIp || ip == myIp; }
static bool isTrusted(uint32_t ip) { return ip == hubIp || (haveBaseline && baseKnows(baseline, ip)); }

// ------------------------------------------------------------------ window
static void windowReset(uint32_t now) {
  memset(&win, 0, sizeof win);
  winStart = now;
}

static void windowAdd(uint32_t ip, size_t size, bool known, bool malformed) {
  win.count++;
  win.bytes += size;
  if (!known) win.unknown++;
  if (malformed) win.malformed++;
  for (int i = 0; i < win.nsenders; i++)
    if (win.s[i].ip == ip) { win.s[i].n++; return; }
  win.distinct++;
  if (win.nsenders < MAX_SENDERS) win.s[win.nsenders++] = {ip, 1};
}

// ------------------------------------------------------------------ schema checks
static bool isHex64(const char* s) {
  if (!s || strlen(s) != hive::SIG_HEX_LEN) return false;
  for (const char* p = s; *p; p++)
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return false;
  return true;
}

static bool oneOf(const char* s, const char* const* list, int n) {
  for (int i = 0; i < n && s; i++)
    if (strcmp(s, list[i]) == 0) return true;
  return false;
}

static const char* const CMDS[] = {"ping", "light_on", "light_off", "status"};
static const char* const REASONS[] = {"flood", "unknown_sender", "malformed"};
static const char* const CTRL_CMDS[] = {"relearn", "reset"};

static bool envelopeOk(JsonDocument& d) {
  return d.is<JsonObject>() && d["v"].is<int>() && d["v"].as<int>() == 1 && d["t"].is<const char*>();
}

static bool validCmd(JsonObject o) {
  if (o.size() != 6) return false;
  const char* src = o["src"].as<const char*>();
  const char* dst = o["dst"].as<const char*>();
  return o["t"] == "cmd" && hive::validNodeId(src) && dst && (strcmp(dst, "*") == 0 || hive::validNodeId(dst)) &&
         oneOf(o["cmd"].as<const char*>(), CMDS, 4) && o["seq"].is<long long>();
}

static bool validVax(JsonObject o, uint32_t* target) {
  if (o.size() != 9 || !(o["t"] == "vax")) return false;
  if (!o["seq"].is<long long>() || !o["ttl"].is<int>()) return false;
  long long seq = o["seq"].as<long long>();
  int ttl = o["ttl"].as<int>();
  return hive::validNodeId(o["issuer"].as<const char*>()) && seq >= 0 && seq < 2147483648LL &&
         o["rule"] == "block" && hive::parseIPv4(o["target"].as<const char*>(), target) && ttl >= 1 &&
         ttl <= MAX_TTL && oneOf(o["reason"].as<const char*>(), REASONS, 3) && isHex64(o["sig"].as<const char*>());
}

// ------------------------------------------------------------------ control (signed by the dashboard)
static void doReset(uint32_t now, const char* why) {
  memset(blocks, 0, sizeof blocks);
  memset(pending, 0, sizeof pending);
  for (int i = 0; i < nIssuers; i++) {
    issuers[i].distrusted = false;
    issuers[i].ntimes = 0;
  }
  hot = 0;
  calm = false;
  cBlocked = cDropped = cIssued = cAdopted = cRejected = 0;
  state = haveBaseline ? HEALTHY : LEARNING;
  windowReset(now);
#if HIVE_BLE
  ble.reset(now);  // un-block cut-off Bluetooth devices; their baselines stay
#endif
  event("heal", why);
}

static void doRelearn(uint32_t now) {
  haveBaseline = false;
  memset(&baseline, 0, sizeof baseline);
  memset(&learnBase, 0, sizeof learnBase);
  saveBaseline();
  learnStart = hubIp ? now : 0;
  doReset(now, "reset by operator");
#if HIVE_BLE
  ble.relearn(now);
#endif
  state = LEARNING;
  event("relearn", "learning normal traffic again");
}

static void onCtrl(JsonObject o, uint32_t now) {
  const char* cmd = o["cmd"].as<const char*>();
  const char* sig = o["sig"].as<const char*>();
  bool ok = o.size() == 5 && oneOf(cmd, CTRL_CMDS, 2) && o["seq"].is<unsigned long long>() && isHex64(sig);
  uint64_t seq = ok ? o["seq"].as<unsigned long long>() : 0;
  if (ok && hasCtrlSeq && seq <= lastCtrlSeq) ok = false;
  if (ok) {
    char canon[120], want[hive::SIG_HEX_LEN + 1];
    int n = hive::canonicalCtrl(canon, sizeof canon, cmd, seq);
    ok = n > 0 && hive::signHex(adminKey, canon, n, want) && hive::sigEquals(want, sig);
  }
  if (!ok) {
    event("ctrl_rejected", "unsigned or replayed control message");
    return;
  }
  hasCtrlSeq = true;
  lastCtrlSeq = seq;
  if (strcmp(cmd, "reset") == 0) doReset(now, "reset by operator");
  else doRelearn(now);
}

// ------------------------------------------------------------------ data port pipeline
static void onData(uint32_t ip, const char* buf, size_t len, size_t fullLen, uint32_t now) {
  Block* b = findBlock(ip, now);
  if (b) {
    cBlocked++;
    if (!b->logged) {
      b->logged = true;
      char ipS[16], msg[80];
      ipText(ip, ipS);
      snprintf(msg, sizeof msg, "dropped first packet from %s (immune)", ipS);
      event("blocked_first_packet", msg, ip);
    }
    return;
  }

  JsonDocument doc;
  bool parsed = fullLen <= (size_t)MAX_MSG && !deserializeJson(doc, buf, len) && envelopeOk(doc);
  if (parsed && doc["t"] == "ctrl") {
    onCtrl(doc.as<JsonObject>(), now);
    return;
  }
  if (state == QUARANTINED && !isTrusted(ip)) {
    cDropped++;
    return;
  }

  bool ok = parsed && validCmd(doc.as<JsonObject>());
  if (ok && hubIp == 0 && doc["src"] == "hub") hubIp = ip;
  if (ok && ip == hubIp && state == LEARNING && learnStart == 0) {
    learnStart = now ? now : 1;
    windowReset(now);
    memset(&learnBase, 0, sizeof learnBase);
  }
  bool learning = state == LEARNING;
  bool known = learning || ip == hubIp || (haveBaseline && baseKnows(baseline, ip));
  windowAdd(ip, fullLen, known, !ok);
  if (learning && learnStart) baseRemember(learnBase, ip);
  if (!ok) return;
  const char* cmd = doc["cmd"].as<const char*>();
  if (strcmp(cmd, "light_on") == 0) light = true;
  else if (strcmp(cmd, "light_off") == 0) light = false;
}

// ------------------------------------------------------------------ vaccine pipeline
static int findIssuer(const char* id) {
  for (int i = 0; i < nIssuers; i++)
    if (strcmp(issuers[i].id, id) == 0) return i;
  return -1;
}

static void onVax(uint32_t ip, const char* buf, size_t len, size_t fullLen, uint32_t now) {
  char ipS[16], msg[160];
  ipText(ip, ipS);
  if (fullLen > (size_t)MAX_VAX) {
    snprintf(msg, sizeof msg, "%u bytes from %s", (unsigned)fullLen, ipS);
    return reject("garbage", msg);
  }
  JsonDocument doc;
  uint32_t target = 0;
  if (deserializeJson(doc, buf, len) || !envelopeOk(doc) || !validVax(doc.as<JsonObject>(), &target)) {
    snprintf(msg, sizeof msg, "bad format from %s", ipS);
    return reject("garbage", msg);
  }
  const char* issuerId = doc["issuer"].as<const char*>();
  if (strcmp(issuerId, NODE_ID) == 0) return;  // our own broadcast echo
  int idx = findIssuer(issuerId);
  if (idx < 0) return reject("unknown_issuer", issuerId);
  Issuer& is = issuers[idx];
  if (is.distrusted && !reached(now, is.distrustUntil)) {
    snprintf(msg, sizeof msg, "%s is in autoimmune timeout", issuerId);
    return reject("distrusted", msg);
  }
  is.distrusted = false;

  uint32_t seq = (uint32_t)doc["seq"].as<long long>();
  int ttl = doc["ttl"].as<int>();
  const char* reason = doc["reason"].as<const char*>();
  const char* sig = doc["sig"].as<const char*>();
  char targetS[16], canon[200], want[hive::SIG_HEX_LEN + 1];
  ipText(target, targetS);
  int n = hive::canonicalVax(canon, sizeof canon, issuerId, seq, targetS, ttl, reason);
  if (n < 0) return reject("garbage", "too long");

  if (is.hasSeq && seq == is.lastSeq && strcmp(canon, is.lastCanon) == 0 && strcmp(sig, is.lastSig) == 0)
    return;  // same vaccine via broadcast and unicast
  if (is.hasSeq && seq <= is.lastSeq) {
    snprintf(msg, sizeof msg, "%s seq %lu", issuerId, (unsigned long)seq);
    return reject("replay", msg);
  }
  if (!hive::signHex(is.key, canon, n, want) || !hive::sigEquals(want, sig)) {
    snprintf(msg, sizeof msg, "bad signature claiming %s", issuerId);
    return reject("forged", msg);
  }
  is.hasSeq = true;
  is.lastSeq = seq;
  strncpy(is.lastCanon, canon, sizeof is.lastCanon - 1);
  strncpy(is.lastSig, sig, sizeof is.lastSig - 1);

  // Rate limit (autoimmune): keep accept times from the last 60 s plus this one.
  uint8_t k = 0;
  for (uint8_t i = 0; i < is.ntimes; i++)
    if (!reached(now, is.times[i] + 60000UL)) is.times[k++] = is.times[i];
  if (k == RATE_SLOTS) {
    memmove(is.times, is.times + 1, (RATE_SLOTS - 1) * sizeof(uint32_t));
    k--;
  }
  is.times[k++] = now;
  is.ntimes = k;
  if (k > VAX_RATE_MAX_PER_MIN) {
    is.distrusted = true;
    is.distrustUntil = now + DISTRUST_S * 1000UL;
    for (auto& p : pending) p.vote[idx] = 0;
    snprintf(msg, sizeof msg, "%s sent %u vaccines in 60 s, distrusted", issuerId, (unsigned)k);
    return reject("autoimmune", msg);
  }

  if (isProtected(target)) {
    snprintf(msg, sizeof msg, "%s tried to block %s", issuerId, targetS);
    return reject("protected_target", msg);
  }

  Block* existing = findBlock(target, now);
  if (existing) {
    uint32_t until = now + (uint32_t)ttl * 1000UL;
    if ((int32_t)(until - existing->until) > 0) existing->until = until;
    snprintf(msg, sizeof msg, "%s already blocked (confirmed by %s)", targetS, issuerId);
    return event("vax_pending", msg, target);
  }

  Pending* p = nullptr;
  for (auto& q : pending)
    if (q.used && q.target == target) p = &q;
  if (!p)
    for (auto& q : pending)
      if (!q.used) { p = &q; break; }
  if (!p) p = &pending[0];  // full: recycle
  if (!p->used || p->target != target) {
    memset(p, 0, sizeof *p);
    p->used = true;
    p->target = target;
  }
  p->vote[idx] = now ? now : 1;
  int votes = 0;
  String who;
  for (int i = 0; i < nIssuers; i++)
    if (p->vote[i] && !reached(now, p->vote[i] + PENDING_S * 1000UL)) {
      votes++;
      if (who.length()) who += ", ";
      who += issuers[i].id;
    }
  if (votes >= QUORUM) {
    addBlock(target, ttl, now);
    cAdopted++;
    snprintf(msg, sizeof msg, "immune to %s (reports from %s)", targetS, who.c_str());
    event("vax_adopted", msg, target);
  } else {
    snprintf(msg, sizeof msg, "%s pending %d/%d (from %s)", targetS, votes, QUORUM, issuerId);
    event("vax_pending", msg, target);
  }
}

// ------------------------------------------------------------------ detection response
static uint32_t culprit() {
  uint32_t best = 0, bestUnknown = 0;
  uint16_t n = 0, nUnknown = 0;
  for (int i = 0; i < win.nsenders; i++) {
    const Sender& s = win.s[i];
    if (isProtected(s.ip)) continue;
    if (s.n > n) { n = s.n; best = s.ip; }
    if (!baseKnows(baseline, s.ip) && s.n > nUnknown) { nUnknown = s.n; bestUnknown = s.ip; }
  }
  return bestUnknown ? bestUnknown : best;
}

static const char* pickReason() {
  float z[NF], m = 0;
  baseZ(baseline, features, z);
  for (int i = 0; i < NF; i++) m = fmaxf(m, fabsf(z[i]));
  if (fabsf(z[3]) >= m * 0.5f && features[3] > 0.2f) return "malformed";
  if (fabsf(z[2]) >= m * 0.5f && features[2] > 0.2f) return "unknown_sender";
  return "flood";
}

static void broadcastVax(const char* canon, int n, const char* sig) {
  char full[MAX_VAX + 80];
  // canonical text minus its closing brace, plus the signature
  snprintf(full, sizeof full, "%.*s,\"sig\":\"%s\"}", n - 1, canon, sig);
  uint32_t t[2];
  int k = broadcastTargets(t);
  for (int i = 0; i < k; i++) sendTo(vaxUdp, t[i], VAX_PORT, full, strlen(full));
}

static void respond(uint32_t now) {
  uint32_t c = culprit();
  if (c && findBlock(c, now)) return;
  char cS[16], msg[160];
  ipText(c, cS);
  if (state != QUARANTINED) {
    state = QUARANTINED;
    calm = false;
    snprintf(msg, sizeof msg, "score %.1f > %.1f; culprit %s", score, (double)DET_THRESHOLD, c ? cS : "unknown");
    event("quarantine", msg, c);
  }
  if (!c) return;
  addBlock(c, VAX_TTL_S, now);
  vaxSeq++;
  prefs.putUInt("seq", vaxSeq);
  const char* reason = pickReason();
  char canon[200], sig[hive::SIG_HEX_LEN + 1];
  int n = hive::canonicalVax(canon, sizeof canon, NODE_ID, vaxSeq, cS, VAX_TTL_S, reason);
  if (n > 0 && hive::signHex(myKey, canon, n, sig)) {
    broadcastVax(canon, n, sig);
    cIssued++;
    snprintf(msg, sizeof msg, "block %s (%s), seq %lu", cS, reason, (unsigned long)vaxSeq);
    event("vax_issued", msg, c);
  }
}

static void tick(uint32_t now) {
  for (auto& b : blocks)
    if (b.used && reached(now, b.until)) {
      b.used = false;
      char ipS[16], msg[60];
      ipText(b.ip, ipS);
      snprintf(msg, sizeof msg, "block on %s expired", ipS);
      event("unblock", msg, b.ip);
    }
  for (auto& p : pending) {
    if (!p.used) continue;
    bool any = false;
    for (int i = 0; i < nIssuers; i++) {
      if (p.vote[i] && reached(now, p.vote[i] + PENDING_S * 1000UL)) p.vote[i] = 0;
      any |= p.vote[i] != 0;
    }
    if (!any) p.used = false;
  }

  uint32_t elapsed = now - winStart;
  if (elapsed < (uint32_t)WINDOW_MS) return;
  float secs = elapsed / 1000.0f;
  uint16_t count = win.count;
  features[0] = count / secs;
  features[1] = win.distinct;
  features[2] = count ? (float)win.unknown / count : 0;
  features[3] = count ? (float)win.malformed / count : 0;
  features[4] = count ? (float)win.bytes / count : 0;
  if (count == 0) {  // an empty window says nothing about message size
    const Baseline& ref = haveBaseline ? baseline : learnBase;
    if (ref.n) features[4] = ref.mean[4];
  }

  if (state == LEARNING) {
    windowReset(now);
    if (!learnStart) return;
    baseAdd(learnBase, features);
    if (reached(now, learnStart + LEARN_SECONDS * 1000UL) && learnBase.n >= 3) {
      baseline = learnBase;
      baseline.magic = BASELINE_MAGIC;
      if (hubIp) baseRemember(baseline, hubIp);
      haveBaseline = true;
      state = HEALTHY;
      saveBaseline();
      char msg[80];
      snprintf(msg, sizeof msg, "baseline from %lu windows, %lu known sender(s)", (unsigned long)baseline.n,
               (unsigned long)baseline.nknown);
      event("learned", msg);
    }
    return;
  }

  score = detectorScore(features);
  bool anomalous = score > DET_THRESHOLD;
  hot = anomalous ? hot + 1 : 0;
  if (anomalous && hot >= CONSECUTIVE) respond(now);
  windowReset(now);
  if (state == QUARANTINED) {
    if (anomalous) calm = false;
    else if (!calm) {
      calm = true;
      calmSince = now;
    } else if (reached(now, calmSince + QUARANTINE_HOLD_S * 1000UL)) {
      state = HEALTHY;
      calm = false;
      char msg[60];
      snprintf(msg, sizeof msg, "normal for %d s, leaving quarantine", QUARANTINE_HOLD_S);
      event("heal", msg);
    }
  }
}

// ------------------------------------------------------------------ status
static void sendStatus(uint32_t now) {
  JsonDocument doc;
  doc["v"] = 1;
  doc["t"] = "status";
  doc["node"] = NODE_ID;
  doc["kind"] = "esp32";
  doc["state"] = STATE_NAMES[state];
  doc["score"] = roundf(score * 100) / 100;
  doc["thr"] = DET_THRESHOLD;
  doc["det"] = DET_NAME;
  doc["model_bytes"] = MODEL_BYTES;
  JsonArray f = doc["features"].to<JsonArray>();
  for (int i = 0; i < NF; i++) f.add(roundf(features[i] * 100) / 100);
  doc["blocked"] = cBlocked;
  doc["vax_issued"] = cIssued;
  doc["vax_adopted"] = cAdopted;
  doc["vax_rejected"] = cRejected;
  JsonArray bl = doc["blocklist"].to<JsonArray>();
  for (auto& b : blocks)
    if (b.used && !reached(now, b.until)) {
      char s[16];
      ipText(b.ip, s);
      bl.add(s);
    }
  JsonArray pe = doc["pending"].to<JsonArray>();
  for (auto& p : pending) {
    if (!p.used) continue;
    int votes = 0;
    for (int i = 0; i < nIssuers; i++) votes += p.vote[i] != 0;
    char s[16];
    ipText(p.target, s);
    JsonArray e = pe.add<JsonArray>();
    e.add(s);
    e.add(votes);
  }
  doc["quorum"] = QUORUM;
  doc["light"] = light;
  float learn = 1.0f;
  if (state == LEARNING) learn = learnStart ? fminf(1.0f, (now - learnStart) / (LEARN_SECONDS * 1000.0f)) : 0.0f;
  doc["learn"] = roundf(learn * 100) / 100;
  char ip[16];
  ipText(myIp, ip);
  doc["ip"] = ip;
  char out[900];
  size_t len = serializeJson(doc, out, sizeof out);
  sendStatusJson(out, len);
}

// ------------------------------------------------------------------ Bluetooth hub
#if HIVE_BLE
// Feed Bluetooth events to the watcher, cut off whoever it asks for, report its events.
static void bleService(uint32_t now) {
  hive::BleRx r;
  while (hive::bleGluePop(&r)) {
    if (r.kind == hive::BLE_RX_CONNECT) ble.onConnect(r.addr, now);
    else if (r.kind == hive::BLE_RX_DISCONNECT) ble.onDisconnect(r.addr, now);
    else ble.onWrite(r.addr, r.data, r.len < sizeof r.data ? r.len : sizeof r.data, r.len, now);
  }
  ble.tick(now);
  hive::bleGlueTick(now);
  uint8_t kick[6];
  while (ble.popKick(kick)) hive::bleGlueDisconnect(kick);
  hive::BleWatch::Event e;
  while (ble.popEvent(&e)) event(e.kind, e.detail);
}

// One status per Bluetooth device, so the dashboard shows each as its own tile.
static void bleSendStatus(uint32_t now) {
  static const char* names[] = {"learning", "healthy", "quarantined"};
  for (auto& d : ble.dev) {
    if (!d.used) continue;
    char id[12], addr[18];
    snprintf(id, sizeof id, "ble-%02x%02x", d.addr[4], d.addr[5]);
    hive::bleAddrText(d.addr, addr);
    JsonDocument doc;
    doc["v"] = 1;
    doc["t"] = "status";
    doc["node"] = id;
    doc["kind"] = "ble";
    doc["label"] = hive::BleWatch::label(&d);
    doc["state"] = d.state == hive::BleWatch::QUARANTINED ? "quarantined" : (d.connected ? names[d.state] : "offline");
    doc["score"] = roundf(d.score * 100) / 100;
    doc["thr"] = ble.threshold();
    JsonArray f = doc["features"].to<JsonArray>();
    f.add(roundf(d.f[0] * 100) / 100);
    f.add(roundf(d.f[1] * 100) / 100);
    doc["addr"] = addr;
    doc["by"] = NODE_ID;
    doc["light"] = d.light;
    doc["learn"] = roundf(ble.learnProgress(d, now) * 100) / 100;
    char out[400];
    size_t len = serializeJson(doc, out, sizeof out);
    sendStatusJson(out, len);
  }
}
#endif

// ------------------------------------------------------------------ LED, Wi-Fi, serial
static void updateLed(uint32_t now) {
  if (WiFi.status() != WL_CONNECTED) return ledWrite(now % 2000 < 100);
  switch (state) {
    case LEARNING: return ledWrite(now % 1000 < 500);
    case QUARANTINED: return ledWrite(now % 125 < 62);
    default: return ledWrite(light);
  }
}

static void ensureWifi(uint32_t now) {
  if (WiFi.status() == WL_CONNECTED) {
    uint32_t ip = (uint32_t)WiFi.localIP();
    if (ip != myIp) {
      myIp = ip;
      char s[16];
      ipText(myIp, s);
      Serial.printf("[%s] Wi-Fi up, ip %s\n", NODE_ID, s);
    }
    return;
  }
  // Give each attempt time to finish: with Bluetooth sharing the radio, joining can take
  // several seconds, and restarting it every few seconds means it never completes.
  if (lastWifiTry == 0 || now - lastWifiTry > 20000) {
    lastWifiTry = now ? now : 1;
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASS);
  }
}

static void serialCommands(uint32_t now) {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == 'r') doRelearn(now);
    else if (c == 'x') doReset(now, "reset from serial");
    else if (c == 's') {
      char ip[16], hub[16];
      ipText(myIp, ip);
      ipText(hubIp, hub);
      Serial.printf("[%s] %s ip=%s hub=%s score=%.2f/%.1f f=[%.1f %.0f %.2f %.2f %.0f] blocked=%lu seq=%lu\n",
                    NODE_ID, STATE_NAMES[state], ip, hub, score, (double)DET_THRESHOLD, features[0], features[1],
                    features[2], features[3], features[4], (unsigned long)cBlocked, (unsigned long)vaxSeq);
#if HIVE_BLE
      for (auto& d : ble.dev) {
        if (!d.used) continue;
        char addr[18];
        hive::bleAddrText(d.addr, addr);
        Serial.printf("[%s] ble %s %s state=%d connected=%d score=%.1f f=[%.1f %.2f]%s\n", NODE_ID,
                      hive::BleWatch::label(&d), addr, d.state, d.connected, d.score, d.f[0], d.f[1],
                      ble.isBlocked(d.addr) ? " BLOCKED" : "");
      }
#endif
    }
  }
}

static void readPackets(WiFiUDP& udp, bool vax, uint32_t now) {
  for (int k = 0; k < 64; k++) {
    int size = udp.parsePacket();
    if (size <= 0) return;
    uint32_t ip = (uint32_t)udp.remoteIP();
    int len = udp.read(rxBuf, MAX_MSG);
    if (len < 0) len = 0;
    rxBuf[len] = 0;
    // Drop whatever is left of an oversized datagram. The core's parsePacket() returns 0
    // while any of the previous packet is unread, so one 600-byte packet would otherwise
    // deafen this port for good (found on real hardware; covered by test_firmware.cpp).
    udp.clear();
    if (vax) onVax(ip, rxBuf, len, size, now);
    else onData(ip, rxBuf, len, size, now);
  }
}

// ------------------------------------------------------------------ Arduino entry points
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  ledWrite(false);
  delay(200);
  Serial.printf("\n[%s] Hive node booting (detector %s, %d bytes)\n", NODE_ID, DET_NAME, MODEL_BYTES);

  hive::hexToBytes(NODE_KEY_HEX, myKey, hive::KEY_LEN);
  hive::hexToBytes(ADMIN_KEY_HEX, adminKey, hive::KEY_LEN);
  for (int i = 0; i < N_ISSUERS && nIssuers < MAX_ISSUERS; i++) {
    Issuer& is = issuers[nIssuers];
    memset(&is, 0, sizeof is);
    is.id = ISSUERS[i].id;
    if (hive::hexToBytes(ISSUERS[i].key_hex, is.key, hive::KEY_LEN)) nIssuers++;
  }
  hive::parseIPv4(HUB_IP, &hubIp);
  hive::parseIPv4(DASHBOARD_IP, &dashIp);

  prefs.begin("hive", false);
  loadPersisted();
  Serial.printf("[%s] %s, vaccine seq %lu, %d issuers\n", NODE_ID,
                haveBaseline ? "baseline loaded from flash" : "no baseline yet: will learn", (unsigned long)vaxSeq,
                nIssuers);

  WiFi.mode(WIFI_STA);
  // Without Bluetooth, modem sleep stays off so broadcast vaccines arrive at once. With
  // the Bluetooth hub, Espressif requires modem sleep for Wi-Fi/Bluetooth coexistence.
  WiFi.setSleep(HIVE_BLE ? true : false);
  ensureWifi(millis());
  dataUdp.begin(DATA_PORT);
  vaxUdp.begin(VAX_PORT);
  windowReset(millis());
}

#if HIVE_BLE
// The Bluetooth hub starts once Wi-Fi is up (or after 15 s regardless), so joining the
// hotspot gets the radio to itself.
static void startBluetoothWhenReady(uint32_t now) {
  static bool started = false;
  if (started || (WiFi.status() != WL_CONNECTED && now < 15000)) return;
  started = true;
  hive::bleGlueBegin(BLE_HUB_NAME);
  Serial.printf("[%s] Bluetooth hub advertising as %s\n", NODE_ID, BLE_HUB_NAME);
}
#endif

void loop() {
  uint32_t now = millis();
  ensureWifi(now);
  if (WiFi.status() == WL_CONNECTED) {
    readPackets(dataUdp, false, now);
    readPackets(vaxUdp, true, now);
  }
  tick(now);
#if HIVE_BLE
  startBluetoothWhenReady(now);
  bleService(now);
#endif
  if (reached(now, nextStatus)) {
    nextStatus = now + 1000;
    if (WiFi.status() == WL_CONNECTED) {
      sendStatus(now);
#if HIVE_BLE
      bleSendStatus(now);
#endif
    }
  }
  updateLed(now);
  serialCommands(now);
  delay(2);
}
