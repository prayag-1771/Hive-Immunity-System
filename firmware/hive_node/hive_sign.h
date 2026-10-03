// Canonical message bytes + HMAC-SHA256 for Hive vaccines and control messages.
//
// Portable on purpose: on the ESP32 the HMAC comes from mbedtls, on a PC from OpenSSL,
// so firmware/test/test_sign.cpp can check this exact code against the shared test
// vector (tests/test_hmac_vector.py) without a board.
//
// The canonical form must match Python's
//   json.dumps(msg_without_sig, sort_keys=True, separators=(",", ":"))
// Fields are validated first (node ids, canonical IPv4, fixed enums), so no JSON
// escaping is ever needed and the strings can be built by hand in sorted-key order.
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef ARDUINO
#include "mbedtls/md.h"
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

namespace hive {

static const size_t KEY_LEN = 32;
static const size_t SIG_HEX_LEN = 64;

inline int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline bool hexToBytes(const char* hex, uint8_t* out, size_t n) {
  if (strlen(hex) != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

inline void bytesToHex(const uint8_t* in, size_t n, char* out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = digits[in[i] >> 4];
    out[2 * i + 1] = digits[in[i] & 15];
  }
  out[2 * n] = 0;
}

inline bool hmacSha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
#ifdef ARDUINO
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md_hmac(info, key, klen, msg, mlen, out) == 0;
#else
  unsigned int len = 0;
  return HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &len) != nullptr && len == 32;
#endif
}

// Lowercase hex HMAC of msg[0..len) -> out (65 bytes incl. terminator).
inline bool signHex(const uint8_t key[KEY_LEN], const char* msg, size_t len, char out[SIG_HEX_LEN + 1]) {
  uint8_t mac[32];
  if (!hmacSha256(key, KEY_LEN, (const uint8_t*)msg, len, mac)) return false;
  bytesToHex(mac, 32, out);
  return true;
}

// Compares two 64-char hex signatures without an early exit.
inline bool sigEquals(const char* a, const char* b) {
  if (strlen(a) != SIG_HEX_LEN || strlen(b) != SIG_HEX_LEN) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < SIG_HEX_LEN; i++) diff |= (uint8_t)(a[i] ^ b[i]);
  return diff == 0;
}

// [A-Za-z0-9_-]{1,16}, same as hive_core.NODE_ID_RE
inline bool validNodeId(const char* s) {
  size_t n = s ? strlen(s) : 0;
  if (n < 1 || n > 16) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    if (!ok) return false;
  }
  return true;
}

// Strict dotted quad: exactly 4 parts, 0-255, no leading zeros, no spaces, so the text
// is identical to Python's str(ipaddress.IPv4Address(s)). Result in network order
// (first octet in the lowest byte), matching Arduino's IPAddress uint32 cast.
inline bool parseIPv4(const char* s, uint32_t* out) {
  if (!s) return false;
  uint32_t ip = 0;
  int part = 0;
  const char* p = s;
  while (part < 4) {
    if (*p < '0' || *p > '9') return false;
    int v = 0, digits = 0;
    const char* start = p;
    while (*p >= '0' && *p <= '9') {
      v = v * 10 + (*p - '0');
      if (++digits > 3 || v > 255) return false;
      p++;
    }
    if (digits > 1 && *start == '0') return false;
    ip |= (uint32_t)v << (8 * part);
    part++;
    if (part < 4) {
      if (*p != '.') return false;
      p++;
    }
  }
  if (*p != 0) return false;
  *out = ip;
  return true;
}

inline void formatIPv4(uint32_t ip, char out[16]) {
  snprintf(out, 16, "%u.%u.%u.%u", (unsigned)(ip & 255), (unsigned)((ip >> 8) & 255),
           (unsigned)((ip >> 16) & 255), (unsigned)(ip >> 24));
}

// Decimal text of a uint64 (printf's %llu is not guaranteed on every libc).
inline void u64ToDec(uint64_t v, char out[21]) {
  char tmp[21];
  int n = 0;
  do {
    tmp[n++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v);
  for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
  out[n] = 0;
}

// {"issuer":..,"reason":..,"rule":"block","seq":..,"t":"vax","target":..,"ttl":..,"v":1}
inline int canonicalVax(char* buf, size_t cap, const char* issuer, uint32_t seq, const char* target,
                        int ttl, const char* reason) {
  int n = snprintf(buf, cap,
                   "{\"issuer\":\"%s\",\"reason\":\"%s\",\"rule\":\"block\",\"seq\":%lu,"
                   "\"t\":\"vax\",\"target\":\"%s\",\"ttl\":%d,\"v\":1}",
                   issuer, reason, (unsigned long)seq, target, ttl);
  return (n > 0 && (size_t)n < cap) ? n : -1;
}

// {"cmd":..,"seq":..,"t":"ctrl","v":1}
inline int canonicalCtrl(char* buf, size_t cap, const char* cmd, uint64_t seq) {
  char num[21];
  u64ToDec(seq, num);
  int n = snprintf(buf, cap, "{\"cmd\":\"%s\",\"seq\":%s,\"t\":\"ctrl\",\"v\":1}", cmd, num);
  return (n > 0 && (size_t)n < cap) ? n : -1;
}

}  // namespace hive
