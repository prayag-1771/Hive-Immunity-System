// Runs the real hive_node.ino on a PC with mocked Wi-Fi/UDP/NVS and checks it behaves
// like agent/hive_core.py: learning, detection, quarantine, vaccines, every rejection
// path, signed reset, persistence across a reboot.
//
//   sh firmware/test/run_host_test.sh
#include <random>

#include "Arduino.h"
#include "Preferences.h"
#include "WiFi.h"
#include "WiFiUdp.h"

#include "../hive_node/hive_node.ino"

static int failures = 0;
#define CHECK(cond)                                                              \
  do {                                                                           \
    if (!(cond)) {                                                               \
      std::printf("FAIL %s:%d  %s  (t=%u ms)\n", __FILE__, __LINE__, #cond, g_millis); \
      failures++;                                                                \
    }                                                                            \
  } while (0)

static const uint32_t ME = IPAddress(10, 0, 0, 2);
static const uint32_t HUB = IPAddress(10, 0, 0, 1);
static const uint32_t LAPB = IPAddress(10, 0, 0, 4);
static const uint32_t ATTACKER = IPAddress(10, 0, 0, 66);
static const char* KEY_LAPB = "3333333333333333333333333333333333333333333333333333333333333333";
static const char* KEY_GW = "4444444444444444444444444444444444444444444444444444444444444444";
static const char* KEY_ROGUE = "5555555555555555555555555555555555555555555555555555555555555555";
static const char* KEY_ADMIN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static std::mt19937 rng(7);
static int hubSeq = 0;

static void inject(uint16_t port, uint32_t from, const std::string& data) { g_inbox[port].push_back({from, port, data}); }

static std::string hubCmd(const char* cmd = "ping") {
  char b[120];
  snprintf(b, sizeof b, "{\"v\":1,\"t\":\"cmd\",\"src\":\"hub\",\"dst\":\"esp32\",\"cmd\":\"%s\",\"seq\":%d}", cmd,
           ++hubSeq);
  return b;
}

static std::string junk() {
  static int k = 0;
  if (++k % 4 == 0) return std::string(600, 'A');  // like tools/scenarios.py: some oversized
  std::string s;
  int n = 20 + rng() % 80;
  for (int i = 0; i < n; i++) s += (char)(rng() % 256);
  return s;
}

static std::string signedVax(const char* issuer, const char* keyHex, uint32_t seq, const char* target,
                             int ttl = 300, const char* reason = "flood") {
  uint8_t key[32];
  hive::hexToBytes(keyHex, key, 32);
  char canon[200], sig[65], full[300];
  int n = hive::canonicalVax(canon, sizeof canon, issuer, seq, target, ttl, reason);
  hive::signHex(key, canon, n, sig);
  snprintf(full, sizeof full, "%.*s,\"sig\":\"%s\"}", n - 1, canon, sig);
  return full;
}

static std::string signedCtrl(const char* cmd, uint64_t seq) {
  uint8_t key[32];
  hive::hexToBytes(KEY_ADMIN, key, 32);
  char canon[120], sig[65], full[200];
  int n = hive::canonicalCtrl(canon, sizeof canon, cmd, seq);
  hive::signHex(key, canon, n, sig);
  snprintf(full, sizeof full, "%.*s,\"sig\":\"%s\"}", n - 1, canon, sig);
  return full;
}

// Advance simulated time, feeding hub traffic (~3/s) and optional attack traffic.
static void run(uint32_t ms, int attackPerSec = 0) {
  uint32_t end = g_millis + ms;
  uint32_t nextAttack = g_millis;
  std::uniform_real_distribution<double> u(0, 1);
  while ((int32_t)(end - g_millis) > 0) {
    if (u(rng) < 3.0 * 0.002) inject(DATA_PORT, HUB, hubCmd(u(rng) < 0.2 ? "light_on" : "ping"));
    if (attackPerSec && (int32_t)(g_millis - nextAttack) >= 0) {
      inject(DATA_PORT, ATTACKER, junk());
      nextAttack += 1000 / attackPerSec;
    }
    loop();  // loop() ends with delay(2)
  }
}

struct Ev {
  std::string kind, detail, target;
};

static std::vector<Ev> drainEvents() {
  std::vector<Ev> out;
  for (auto& p : g_sent) {
    if (p.port != STATUS_PORT) continue;
    JsonDocument d;
    if (deserializeJson(d, p.data)) continue;
    if (d["t"] == "event")
      out.push_back({d["kind"].as<std::string>(), d["detail"].as<std::string>(),
                     d["target"].is<const char*>() ? d["target"].as<std::string>() : ""});
  }
  return out;
}

static std::vector<std::string> sentVaccines() {
  std::vector<std::string> out;
  for (auto& p : g_sent)
    if (p.port == VAX_PORT) out.push_back(p.data);
  return out;
}

static bool has(const std::vector<Ev>& ev, const std::string& kind, const std::string& prefix = "") {
  for (auto& e : ev)
    if (e.kind == kind && e.detail.compare(0, prefix.size(), prefix) == 0) return true;
  return false;
}

static int count(const std::vector<Ev>& ev, const std::string& kind, const std::string& prefix = "") {
  int n = 0;
  for (auto& e : ev)
    if (e.kind == kind && e.detail.compare(0, prefix.size(), prefix) == 0) n++;
  return n;
}

static void boot() {
  g_inbox.clear();
  g_sent.clear();
  memset(blocks, 0, sizeof blocks);
  memset(pending, 0, sizeof pending);
  nIssuers = 0;
  state = LEARNING;
  haveBaseline = false;
  learnStart = 0;
  hubIp = dashIp = myIp = 0;
  hasCtrlSeq = false;
  setup();
}

static JsonDocument lastStatus() {
  JsonDocument d;
  for (auto it = g_sent.rbegin(); it != g_sent.rend(); ++it)
    if (it->port == STATUS_PORT && !deserializeJson(d, it->data) && d["t"] == "status") return d;
  return d;
}

int main() {
  g_my_ip = ME;
  g_millis = 1000;
  boot();

  // 1. Waits for the hub, then learns for LEARN_SECONDS.
  run(3000);
  CHECK(state == LEARNING);
  run(25000);
  CHECK(state == HEALTHY);
  CHECK(hubIp == HUB);
  CHECK(haveBaseline && g_nvs.count("base"));
  CHECK(has(drainEvents(), "learned"));
  g_sent.clear();

  // 2. Ten quiet minutes of normal traffic: no false alarm.
  run(600000);
  auto ev = drainEvents();
  CHECK(!has(ev, "quarantine"));
  CHECK(state == HEALTHY);
  JsonDocument st = lastStatus();
  CHECK(st["state"] == "healthy");
  CHECK(st["kind"] == "esp32");
  CHECK(st["ip"] == "10.0.0.2");
  g_sent.clear();

  // 2b. Oversized datagrams (bigger than the read buffer) must not deafen either port.
  //     Found on real hardware: the ESP32 core delivers nothing more until the rest of a
  //     partly read packet is discarded.
  inject(DATA_PORT, IPAddress(10, 0, 0, 50), std::string(1400, 'B'));
  inject(VAX_PORT, IPAddress(10, 0, 0, 50), std::string(1400, 'B'));
  run(3000);
  CHECK(features[0] > 0.5f);  // hub traffic still counted after the oversized packet
  inject(VAX_PORT, LAPB, signedVax("lapB", KEY_LAPB, 900, "10.0.0.88"));
  run(20);
  CHECK(has(drainEvents(), "vax_pending", "10.0.0.88 pending 1/2"));
  CHECK(state == HEALTHY);
  memset(pending, 0, sizeof pending);
  issuers[findIssuer("lapB")].hasSeq = false;  // later steps reuse lapB's low sequence numbers
  issuers[findIssuer("lapB")].ntimes = 0;
  g_sent.clear();

  // 3. Attack: quarantine + block + one signed vaccine within ~2 windows.
  uint32_t t0 = g_millis;
  while (state != QUARANTINED && g_millis - t0 < 5000) run(10, 50);
  CHECK(state == QUARANTINED);
  CHECK(g_millis - t0 <= 2200);
  run(1000, 50);
  ev = drainEvents();
  CHECK(has(ev, "quarantine"));
  CHECK(has(ev, "vax_issued", "block 10.0.0.66"));
  CHECK(has(ev, "blocked_first_packet"));
  auto vax = sentVaccines();
  CHECK(vax.size() >= 1);
  if (!vax.empty()) {
    // The vaccine on the wire must verify with the node's key, exactly as Python would.
    JsonDocument d;
    CHECK(!deserializeJson(d, vax[0]));
    char canon[200], want[65];
    uint8_t key[32];
    hive::hexToBytes(NODE_KEY_HEX, key, 32);
    int n = hive::canonicalVax(canon, sizeof canon, d["issuer"], d["seq"].as<uint32_t>(), d["target"],
                               d["ttl"].as<int>(), d["reason"]);
    hive::signHex(key, canon, n, want);
    CHECK(d["sig"] == want);
    CHECK(d["target"] == "10.0.0.66");
    CHECK(d["rule"] == "block");
    CHECK(vax[0].size() <= (size_t)MAX_VAX);
  }
  CHECK(prefs.getUInt("seq", 0) == 1);
  g_sent.clear();

  // 4. Heals after QUARANTINE_HOLD_S of normal scores.
  run(33000);
  CHECK(state == HEALTHY);
  CHECK(has(drainEvents(), "heal"));
  g_sent.clear();

  // 5. Quorum: one report pends, a second issuer makes it adopt.
  inject(VAX_PORT, LAPB, signedVax("lapB", KEY_LAPB, 1, "10.0.0.77"));
  run(20);
  CHECK(has(drainEvents(), "vax_pending", "10.0.0.77 pending 1/2"));
  inject(VAX_PORT, HUB, signedVax("gateway", KEY_GW, 1, "10.0.0.77"));
  run(20);
  CHECK(has(drainEvents(), "vax_adopted", "immune to 10.0.0.77 (reports from lapB, gateway)"));
  inject(DATA_PORT, IPAddress(10, 0, 0, 77), "{}");
  run(20);
  CHECK(has(drainEvents(), "blocked_first_packet", "dropped first packet from 10.0.0.77"));
  g_sent.clear();

  // 6. Every rejection path.
  inject(VAX_PORT, LAPB, signedVax("lapB", KEY_LAPB, 1, "10.0.0.78"));  // same seq, new content
  inject(VAX_PORT, ATTACKER, signedVax("lapB", KEY_ROGUE, 99, "10.0.0.78"));
  inject(VAX_PORT, ATTACKER, std::string(400, 'x'));
  inject(VAX_PORT, ATTACKER, "{\"v\":1,\"t\":\"vax\",\"issuer\":\"lapB\"}");
  inject(VAX_PORT, ATTACKER, signedVax("lapZ", KEY_ROGUE, 1, "10.0.0.78"));
  inject(VAX_PORT, ATTACKER, signedVax("rogue", KEY_ROGUE, 1, "10.0.0.1"));  // hub
  inject(VAX_PORT, ATTACKER, signedVax("rogue", KEY_ROGUE, 2, "10.0.0.2"));  // me
  run(50);
  ev = drainEvents();
  CHECK(has(ev, "vax_rejected", "replay: lapB seq 1"));
  CHECK(has(ev, "vax_rejected", "forged: bad signature claiming lapB"));
  CHECK(count(ev, "vax_rejected", "garbage") == 2);
  CHECK(has(ev, "vax_rejected", "unknown_issuer: lapZ"));
  CHECK(count(ev, "vax_rejected", "protected_target") == 2);
  g_sent.clear();

  // Identical duplicate (broadcast + unicast copy) is ignored silently.
  std::string dup = signedVax("lapB", KEY_LAPB, 5, "10.0.0.79");
  inject(VAX_PORT, LAPB, dup);
  inject(VAX_PORT, LAPB, dup);
  run(20);
  ev = drainEvents();
  CHECK(count(ev, "vax_pending", "10.0.0.79") == 1);
  CHECK(!has(ev, "vax_rejected"));
  g_sent.clear();

  // Autoimmune: rogue already used 2 of its 3 per minute above; the 4th trips distrust.
  for (int i = 0; i < 4; i++) {
    char t[16];
    snprintf(t, sizeof t, "198.18.1.%d", i + 1);
    inject(VAX_PORT, ATTACKER, signedVax("rogue", KEY_ROGUE, 10 + i, t));
  }
  run(50);
  ev = drainEvents();
  CHECK(count(ev, "vax_pending", "198.18.1.1 pending 1/2") == 1);
  CHECK(has(ev, "vax_rejected", "autoimmune: rogue sent 4 vaccines in 60 s"));
  CHECK(has(ev, "vax_rejected", "distrusted: rogue"));
  run(1100);
  CHECK(lastStatus()["vax_rejected"].as<int>() == (int)cRejected && cRejected >= 9);
  g_sent.clear();

  // 7. Forged control is refused; signed reset clears state; replayed reset is refused.
  //    (Sent from lapB's address: the attacker's own address is still blocked.)
  inject(DATA_PORT, ATTACKER, signedCtrl("reset", 4));
  run(20);
  CHECK(!has(drainEvents(), "heal"));  // dropped: blocked sender
  inject(DATA_PORT, LAPB, signedCtrl("reset", 5).replace(70, 4, "0000"));
  run(20);
  CHECK(has(drainEvents(), "ctrl_rejected"));
  CHECK(findBlock(IPAddress(10, 0, 0, 77), g_millis) != nullptr);
  inject(DATA_PORT, HUB, signedCtrl("reset", 1791043200123ULL));
  run(20);
  CHECK(findBlock(IPAddress(10, 0, 0, 77), g_millis) == nullptr);
  CHECK(cRejected == 0 && state == HEALTHY);
  inject(DATA_PORT, HUB, signedCtrl("reset", 1791043200123ULL));
  run(20);
  CHECK(has(drainEvents(), "ctrl_rejected"));
  g_sent.clear();

  // 8. Status JSON stays within one datagram even with full tables.
  for (int i = 0; i < MAX_BLOCKS; i++) addBlock(IPAddress(198, 18, 2, i + 1), 300, g_millis);
  for (int i = 0; i < MAX_PENDING; i++) {
    char t[16];
    snprintf(t, sizeof t, "198.18.3.%d", i + 1);
    inject(VAX_PORT, LAPB, signedVax("lapB", KEY_LAPB, 100 + i, t));
    run(5);
  }
  run(1100);
  size_t biggest = 0;
  for (auto& p : g_sent)
    if (p.port == STATUS_PORT) biggest = std::max(biggest, p.data.size());
  CHECK(biggest > 0 && biggest < 900);
  g_sent.clear();

  // 9. Reboot: baseline and vaccine seq come back from NVS, no relearning.
  boot();
  CHECK(state == HEALTHY);
  CHECK(vaxSeq == 1);
  run(5000);
  CHECK(state == HEALTHY);
  CHECK(hubIp == HUB);

  // 10. Relearn via serial.
  g_serial_in.push_back('r');
  run(100);
  CHECK(state == LEARNING);
  run(23000);
  CHECK(state == HEALTHY);

  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("hive_node.ino: all firmware host tests passed\n");
  return 0;
}
