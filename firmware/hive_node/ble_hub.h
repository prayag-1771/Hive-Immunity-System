// Bluetooth (BLE) hub: protects Bluetooth devices that cannot run Hive.
//
// The ESP32 advertises a small GATT service. Bluetooth devices (bulbs, sensors, locks)
// connect and write short reports to it: "<name>:<seq>:<light>", e.g. "blebulb:42:1".
// For each device the hub learns the normal report rate and share of malformed reports;
// when a device starts misbehaving the hub cuts the radio link and refuses every
// reconnection from that Bluetooth address until an operator reset. It is the gateway
// idea from gateway/guardian.py, applied to Bluetooth.
//
// BleWatch is pure logic and runs on a PC in firmware/test. The Bluedroid glue at the
// bottom only exists on the ESP32: its callbacks run in the Bluetooth task and hand
// events to loop() through a small locked queue.
#pragma once

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BLE_SERVICE_UUID "dfa90001-9f19-4d01-a7b2-6d341a4d5745"
#define BLE_REPORT_UUID "dfa90002-9f19-4d01-a7b2-6d341a4d5745"

namespace hive {

// One Bluetooth event handed from the Bluetooth task to loop().
struct BleRx {
  uint8_t kind;
  uint8_t addr[6];
  uint16_t len;      // full length of a write
  uint8_t data[24];  // its first bytes (a report is at most 20)
};
enum : uint8_t { BLE_RX_CONNECT = 1, BLE_RX_DISCONNECT = 2, BLE_RX_WRITE = 3 };

inline void bleAddrText(const uint8_t a[6], char out[18]) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5]);
}

// "<name>:<seq>:<light>" with name [a-z0-9]{1,10}, seq 1-6 digits, light 0 or 1.
inline bool bleValidReport(const uint8_t* d, size_t len, char name[11], bool* light) {
  if (len < 5 || len > 20) return false;
  size_t i = 0, n = 0;
  while (i < len && d[i] != ':') {
    char c = (char)d[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) || ++n > 10) return false;
    i++;
  }
  if (n == 0 || i >= len) return false;
  size_t nameLen = n, digits = 0;
  for (i++; i < len && d[i] != ':'; i++) {
    if (d[i] < '0' || d[i] > '9' || ++digits > 6) return false;
  }
  if (digits == 0 || i + 2 != len || (d[i + 1] != '0' && d[i + 1] != '1')) return false;
  memcpy(name, d, nameLen);
  name[nameLen] = 0;
  *light = d[i + 1] == '1';
  return true;
}

class BleWatch {
 public:
  static const int MAX_DEV = 3;
  static const int MAX_BLOCKED = 8;
  static const int MAX_EVENTS = 12;
  static const int MAX_KICKS = 4;
  enum State : uint8_t { LEARNING, HEALTHY, QUARANTINED };

  struct Dev {
    bool used, connected, learned, light;
    uint8_t addr[6];
    char name[11];
    State state;
    uint32_t learnStart;  // 0 = not started
    uint32_t n;
    float mean[2], m2[2];
    uint16_t writes, malformed;
    float f[2];
    float score;
    int hot;
  };
  struct Event {
    char kind[20];
    char detail[150];
  };

  BleWatch(uint32_t learnMs, uint32_t windowMs, float threshold, int consecutive)
      : learnMs_(learnMs), windowMs_(windowMs), threshold_(threshold), consecutive_(consecutive) {
    memset(dev, 0, sizeof dev);
  }

  Dev dev[MAX_DEV];
  float threshold() const { return threshold_; }

  void onConnect(const uint8_t addr[6], uint32_t now) {
    if (isBlocked(addr)) {
      kick(addr);
      int b = blockedIndex(addr);
      if (b >= 0 && (lastRefused_[b] == 0 || now - lastRefused_[b] >= 5000)) {
        lastRefused_[b] = now ? now : 1;
        char a[18], msg[120];
        bleAddrText(addr, a);
        snprintf(msg, sizeof msg, "refused reconnection from %s %s (cut off earlier)", label(find(addr)), a);
        push("ble_refused", msg);
      }
      return;
    }
    Dev* d = slot(addr);
    if (!d) return;
    d->connected = true;
    if (!d->learned && d->learnStart == 0) d->learnStart = now ? now : 1;
    char a[18], msg[120];
    bleAddrText(addr, a);
    snprintf(msg, sizeof msg, "%s %s connected%s", label(d), a, d->learned ? "" : ", learning its normal behaviour");
    push("ble_connected", msg);
  }

  void onDisconnect(const uint8_t addr[6], uint32_t now) {
    (void)now;
    Dev* d = find(addr);
    if (d) d->connected = false;
  }

  void onWrite(const uint8_t addr[6], const uint8_t* data, size_t stored, size_t fullLen, uint32_t now) {
    (void)now;
    if (isBlocked(addr)) return;
    Dev* d = find(addr);
    if (!d) {
      d = slot(addr);
      if (!d) return;
      d->connected = true;
      if (!d->learned && d->learnStart == 0) d->learnStart = now ? now : 1;
    }
    d->writes++;
    char name[11];
    bool light = false;
    if (fullLen == stored && bleValidReport(data, stored, name, &light)) {
      memcpy(d->name, name, sizeof d->name);
      d->light = light;
    } else {
      d->malformed++;
    }
  }

  void tick(uint32_t now) {
    if (windowStart_ == 0) windowStart_ = now ? now : 1;
    uint32_t elapsed = now - windowStart_;
    if (elapsed < windowMs_) return;
    windowStart_ = now ? now : 1;
    float secs = elapsed / 1000.0f;
    for (auto& d : dev) {
      if (!d.used) continue;
      d.f[0] = d.writes / secs;
      d.f[1] = d.writes ? (float)d.malformed / d.writes : 0.0f;
      d.writes = d.malformed = 0;
      if (d.state == QUARANTINED || !d.connected) {
        d.hot = 0;
        continue;
      }
      if (d.state == LEARNING) {
        learn(d, now);
        continue;
      }
      d.score = score(d);
      d.hot = d.score > threshold_ ? d.hot + 1 : 0;
      if (d.hot >= consecutive_) quarantine(d);
    }
  }

  void reset(uint32_t now) {
    (void)now;
    nBlocked_ = 0;
    for (auto& d : dev) {
      if (!d.used) continue;
      d.hot = 0;
      if (d.state == QUARANTINED) d.state = d.learned ? HEALTHY : LEARNING;
    }
  }

  void relearn(uint32_t now) {
    reset(now);
    for (auto& d : dev) {
      if (!d.used) continue;
      d.learned = false;
      d.n = 0;
      memset(d.mean, 0, sizeof d.mean);
      memset(d.m2, 0, sizeof d.m2);
      d.state = LEARNING;
      d.learnStart = d.connected ? (now ? now : 1) : 0;
    }
  }

  float learnProgress(const Dev& d, uint32_t now) const {
    if (d.state != LEARNING) return 1.0f;
    if (!d.learnStart) return 0.0f;
    float p = (now - d.learnStart) / (float)learnMs_;
    return p > 1.0f ? 1.0f : p;
  }

  bool isBlocked(const uint8_t a[6]) const { return blockedIndex(a) >= 0; }

  bool popEvent(Event* out) {
    if (nEvents_ == 0) return false;
    *out = events_[0];
    memmove(events_, events_ + 1, (nEvents_ - 1) * sizeof(Event));
    nEvents_--;
    return true;
  }

  bool popKick(uint8_t addr[6]) {
    if (nKicks_ == 0) return false;
    memcpy(addr, kicks_[0], 6);
    memmove(kicks_, kicks_ + 1, (nKicks_ - 1) * 6);
    nKicks_--;
    return true;
  }

  static const char* label(const Dev* d) { return d && d->name[0] ? d->name : "Bluetooth device"; }

 private:
  static constexpr float FLOOR[2] = {1.0f, 0.05f};  // reports/s, malformed share

  uint32_t learnMs_, windowMs_;
  float threshold_;
  int consecutive_;
  uint32_t windowStart_ = 0;
  uint8_t blocked_[MAX_BLOCKED][6];
  uint32_t lastRefused_[MAX_BLOCKED] = {0};
  int nBlocked_ = 0;
  Event events_[MAX_EVENTS];
  int nEvents_ = 0;
  uint8_t kicks_[MAX_KICKS][6];
  int nKicks_ = 0;

  Dev* find(const uint8_t a[6]) {
    for (auto& d : dev)
      if (d.used && memcmp(d.addr, a, 6) == 0) return &d;
    return nullptr;
  }

  Dev* slot(const uint8_t a[6]) {
    Dev* d = find(a);
    if (d) return d;
    for (auto& x : dev)
      if (!x.used) { d = &x; break; }
    if (!d)  // full: reuse a disconnected, non-quarantined slot
      for (auto& x : dev)
        if (!x.connected && x.state != QUARANTINED) { d = &x; break; }
    if (!d) return nullptr;
    memset(d, 0, sizeof *d);
    d->used = true;
    memcpy(d->addr, a, 6);
    d->state = LEARNING;
    return d;
  }

  int blockedIndex(const uint8_t a[6]) const {
    for (int i = 0; i < nBlocked_; i++)
      if (memcmp(blocked_[i], a, 6) == 0) return i;
    return -1;
  }

  void push(const char* kind, const char* detail) {
    if (nEvents_ == MAX_EVENTS) return;
    snprintf(events_[nEvents_].kind, sizeof events_[nEvents_].kind, "%s", kind);
    snprintf(events_[nEvents_].detail, sizeof events_[nEvents_].detail, "%s", detail);
    nEvents_++;
  }

  void kick(const uint8_t a[6]) {
    if (nKicks_ < MAX_KICKS) memcpy(kicks_[nKicks_++], a, 6);
  }

  void learn(Dev& d, uint32_t now) {
    d.n++;
    for (int i = 0; i < 2; i++) {
      float delta = d.f[i] - d.mean[i];
      d.mean[i] += delta / d.n;
      d.m2[i] += delta * (d.f[i] - d.mean[i]);
    }
    if (now - d.learnStart >= learnMs_ && d.n >= 3) {
      d.learned = true;
      d.state = HEALTHY;
      char a[18], msg[120];
      bleAddrText(d.addr, a);
      snprintf(msg, sizeof msg, "%s %s: baseline from %lu windows (%.2f reports/s normal)", label(&d), a,
               (unsigned long)d.n, d.mean[0]);
      push("ble_learned", msg);
    }
  }

  float score(const Dev& d) const {
    float m = 0;
    for (int i = 0; i < 2; i++) {
      float sd = d.n > 1 ? sqrtf(d.m2[i] / (d.n - 1)) : 0.0f;
      if (sd < FLOOR[i]) sd = FLOOR[i];
      float z = fabsf(d.f[i] - d.mean[i]) / sd;
      if (z > m) m = z;
    }
    return m;
  }

  void quarantine(Dev& d) {
    d.state = QUARANTINED;
    d.hot = 0;
    if (blockedIndex(d.addr) < 0 && nBlocked_ < MAX_BLOCKED) {
      memcpy(blocked_[nBlocked_], d.addr, 6);
      lastRefused_[nBlocked_] = 0;
      nBlocked_++;
    }
    kick(d.addr);
    char a[18], msg[150];
    bleAddrText(d.addr, a);
    snprintf(msg, sizeof msg, "%s %s cut off: %.0f reports/s, %.0f%% malformed (score %.1f > %.1f); "
             "reconnections refused", label(&d), a, d.f[0], d.f[1] * 100.0f, d.score, threshold_);
    push("ble_quarantine", msg);
  }
};

}  // namespace hive

// ------------------------------------------------------------------ Bluetooth glue
#ifdef ARDUINO
#include <BLEDevice.h>
#include <BLEServer.h>
#include <esp_coexist.h>
#include <esp_gap_ble_api.h>

namespace hive {

static portMUX_TYPE g_bleMux = portMUX_INITIALIZER_UNLOCKED;
static const int BLE_QUEUE = 64;
static BleRx g_bleQueue[BLE_QUEUE];
static volatile int g_bleHead = 0, g_bleTail = 0;
static volatile uint32_t g_bleReadvertiseAt = 0;  // millis() when to advertise again, 0 = no

static void blePush(const BleRx& r) {
  portENTER_CRITICAL(&g_bleMux);
  int next = (g_bleHead + 1) % BLE_QUEUE;
  if (next != g_bleTail) {  // when full, drop: a flood the watcher is already seeing
    g_bleQueue[g_bleHead] = r;
    g_bleHead = next;
  }
  portEXIT_CRITICAL(&g_bleMux);
}

inline bool bleGluePop(BleRx* out) {
  bool ok = false;
  portENTER_CRITICAL(&g_bleMux);
  if (g_bleTail != g_bleHead) {
    *out = g_bleQueue[g_bleTail];
    g_bleTail = (g_bleTail + 1) % BLE_QUEUE;
    ok = true;
  }
  portEXIT_CRITICAL(&g_bleMux);
  return ok;
}

class HubServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer*, esp_ble_gatts_cb_param_t* p) override {
    BleRx r = {};
    r.kind = BLE_RX_CONNECT;
    memcpy(r.addr, p->connect.remote_bda, 6);
    blePush(r);
    // Not right now: advertising while a link is being set up costs the radio time the new
    // link needs. bleGlueTick() resumes it a few seconds later so other devices can join.
    uint32_t at = millis() + 3000;
    g_bleReadvertiseAt = at ? at : 1;
  }
  void onDisconnect(BLEServer*, esp_ble_gatts_cb_param_t* p) override {
    BleRx r = {};
    r.kind = BLE_RX_DISCONNECT;
    memcpy(r.addr, p->disconnect.remote_bda, 6);
    blePush(r);
    BLEDevice::startAdvertising();
  }
};

class HubReportCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic*, esp_ble_gatts_cb_param_t* p) override {
    BleRx r = {};
    r.kind = BLE_RX_WRITE;
    memcpy(r.addr, p->write.bda, 6);
    r.len = p->write.len;
    memcpy(r.data, p->write.value, p->write.len < sizeof r.data ? p->write.len : sizeof r.data);
    blePush(r);
  }
};

inline void bleGlueBegin(const char* name) {
  // LE only: with classic Bluetooth enabled (the core's default BTDM mode), Linux/BlueZ
  // finds the ESP32 by classic inquiry too and tries a classic connection, which fails
  // ("br-connection-canceled"). Releasing classic memory makes the controller start
  // LE-only (and frees RAM).
  btMemRelease(BT_MODE_CLASSIC_BT);
  BLEDevice::init(name);
  // The ESP32 has one 2.4 GHz radio for Wi-Fi and Bluetooth. Hive's Wi-Fi traffic is a few
  // small packets a second, while a Bluetooth link drops if it misses its first connection
  // events, so Bluetooth gets the larger share of radio time.
  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  BLEServer* server = BLEDevice::createServer();
  server->setCallbacks(new HubServerCallbacks());
  BLEService* service = server->createService(BLE_SERVICE_UUID);
  BLECharacteristic* report = service->createCharacteristic(
      BLE_REPORT_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  report->setCallbacks(new HubReportCallbacks());
  service->start();
  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(BLE_SERVICE_UUID);
  adv->setScanResponse(true);
  BLEDevice::startAdvertising();
}

// Called from loop(): resume advertising once a new link has settled.
inline void bleGlueTick(uint32_t now) {
  uint32_t at = g_bleReadvertiseAt;
  if (at && (int32_t)(now - at) >= 0) {
    g_bleReadvertiseAt = 0;
    BLEDevice::startAdvertising();
  }
}

// Cut the radio link itself (BLEServer::disconnect only closes the GATT session).
inline void bleGlueDisconnect(const uint8_t addr[6]) {
  esp_bd_addr_t a;
  memcpy(a, addr, 6);
  esp_ble_gap_disconnect(a);
}

}  // namespace hive
#else
#include "ble_glue_mock.h"  // firmware/test/mock: an injectable queue for the PC harness
#endif
