// In-memory UDP for the PC harness: tests push packets into g_inbox[port] and read
// everything the firmware sent from g_sent.
#pragma once
#include <map>
#include <vector>

#include "WiFi.h"

struct MockPacket {
  uint32_t ip;
  uint16_t port;
  std::string data;
};

inline std::map<uint16_t, std::deque<MockPacket>> g_inbox;
inline std::vector<MockPacket> g_sent;

class WiFiUDP {
 public:
  uint8_t begin(uint16_t port) {
    port_ = port;
    return 1;
  }
  int parsePacket() {
    // Like the ESP32 core's NetworkUDP: while part of the previous datagram is unread,
    // parsePacket() returns 0 and no further packets are delivered until clear().
    if (pos_ < cur_.data.size()) return 0;
    auto& q = g_inbox[port_];
    if (q.empty()) return 0;
    cur_ = q.front();
    q.pop_front();
    pos_ = 0;
    return (int)cur_.data.size();
  }
  IPAddress remoteIP() { return IPAddress(cur_.ip); }
  int read(char* buf, size_t len) {
    size_t n = std::min(len, cur_.data.size() - pos_);
    std::memcpy(buf, cur_.data.data() + pos_, n);
    pos_ += n;
    return (int)n;
  }
  void clear() { pos_ = cur_.data.size(); }  // discard the rest of the current datagram
  void flush() { clear(); }
  int beginPacket(IPAddress ip, uint16_t port) {
    out_ = {(uint32_t)ip, port, ""};
    return 1;
  }
  size_t write(const uint8_t* data, size_t len) {
    out_.data.append((const char*)data, len);
    return len;
  }
  int endPacket() {
    g_sent.push_back(out_);
    return 1;
  }

 private:
  uint16_t port_ = 0;
  MockPacket cur_{};
  size_t pos_ = 0;
  MockPacket out_{};
};
