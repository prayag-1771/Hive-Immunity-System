// Minimal WiFi / IPAddress for the PC harness. IPs are uint32 in network order
// (first octet in the lowest byte), like the ESP32 core.
#pragma once
#include "Arduino.h"

#define WL_CONNECTED 3
#define WL_DISCONNECTED 6
#define WIFI_STA 1

class IPAddress {
 public:
  IPAddress(uint32_t v = 0) : v_(v) {}
  IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d) : v_(a | (b << 8) | (c << 16) | ((uint32_t)d << 24)) {}
  operator uint32_t() const { return v_; }

 private:
  uint32_t v_;
};

inline uint32_t g_my_ip = 0;
inline uint32_t g_mask = 0x00ffffff;  // 255.255.255.0
inline int g_wifi_status = WL_CONNECTED;

struct WiFiMock {
  int status() { return g_wifi_status; }
  IPAddress localIP() { return IPAddress(g_my_ip); }
  IPAddress subnetMask() { return IPAddress(g_mask); }
  void mode(int) {}
  void setSleep(bool) {}
  void disconnect() {}
  void begin(const char*, const char*) {}
};
inline WiFiMock WiFi;
