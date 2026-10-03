// PC stand-in for the Bluedroid glue in ble_hub.h: tests push Bluetooth events into
// g_ble_rx and read back every device the hub kicked off the radio from g_ble_kicked.
#pragma once
#include <array>
#include <cstring>
#include <deque>
#include <vector>

namespace hive {

inline std::deque<BleRx> g_ble_rx;
inline std::vector<std::array<uint8_t, 6>> g_ble_kicked;
inline bool g_ble_started = false;

inline void bleGlueBegin(const char*) { g_ble_started = true; }

inline bool bleGluePop(BleRx* out) {
  if (g_ble_rx.empty()) return false;
  *out = g_ble_rx.front();
  g_ble_rx.pop_front();
  return true;
}

inline void bleGlueDisconnect(const uint8_t addr[6]) {
  std::array<uint8_t, 6> a;
  std::memcpy(a.data(), addr, 6);
  g_ble_kicked.push_back(a);
}

}  // namespace hive
