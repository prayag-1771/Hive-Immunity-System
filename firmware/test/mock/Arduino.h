// Minimal Arduino API for running hive_node.ino on a PC (firmware/test only).
#pragma once

#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <math.h>
#include <string>

#define HIGH 1
#define LOW 0
#define OUTPUT 1

inline uint32_t g_millis = 0;
inline int g_led = 0;
inline bool g_verbose = std::getenv("HIVE_VERBOSE") != nullptr;
inline std::deque<char> g_serial_in;

inline uint32_t millis() { return g_millis; }
inline void delay(uint32_t ms) { g_millis += ms; }
inline void pinMode(int, int) {}
inline void digitalWrite(int, int v) { g_led = v; }

class String {
 public:
  String() = default;
  String(const char* s) : s_(s ? s : "") {}
  size_t length() const { return s_.size(); }
  const char* c_str() const { return s_.c_str(); }
  String& operator+=(const char* s) {
    s_ += s ? s : "";
    return *this;
  }
  String& operator+=(const String& o) {
    s_ += o.s_;
    return *this;
  }

 private:
  std::string s_;
};

struct SerialMock {
  void begin(int) {}
  int printf(const char* fmt, ...) {
    if (!g_verbose) return 0;
    va_list ap;
    va_start(ap, fmt);
    int n = std::vprintf(fmt, ap);
    va_end(ap);
    return n;
  }
  int available() { return (int)g_serial_in.size(); }
  int read() {
    if (g_serial_in.empty()) return -1;
    char c = g_serial_in.front();
    g_serial_in.pop_front();
    return c;
  }
};
inline SerialMock Serial;
