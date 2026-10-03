// In-memory NVS for the PC harness. g_nvs survives a simulated reboot.
#pragma once
#include <map>
#include <vector>

#include "Arduino.h"

inline std::map<std::string, std::vector<uint8_t>> g_nvs;

class Preferences {
 public:
  bool begin(const char*, bool = false) { return true; }
  bool isKey(const char* k) { return g_nvs.count(k) != 0; }
  size_t putBytes(const char* k, const void* v, size_t n) {
    g_nvs[k] = std::vector<uint8_t>((const uint8_t*)v, (const uint8_t*)v + n);
    return n;
  }
  size_t getBytes(const char* k, void* out, size_t n) {
    auto it = g_nvs.find(k);
    if (it == g_nvs.end()) return 0;
    size_t m = std::min(n, it->second.size());
    std::memcpy(out, it->second.data(), m);
    return m;
  }
  size_t putUInt(const char* k, uint32_t v) { return putBytes(k, &v, sizeof v); }
  uint32_t getUInt(const char* k, uint32_t def = 0) {
    uint32_t v = def;
    return getBytes(k, &v, sizeof v) == sizeof v ? v : def;
  }
  bool remove(const char* k) { return g_nvs.erase(k) != 0; }
};
