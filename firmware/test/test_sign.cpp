// Host test for firmware/hive_node/hive_sign.h against the vectors the Python side uses.
//
//   g++ -std=c++17 -Wall -Wextra -o test_sign firmware/test/test_sign.cpp -lcrypto && ./test_sign
//   (or: sh firmware/test/run_host_test.sh)
#include <cstdio>
#include <cstring>

#include "../hive_node/hive_sign.h"

static int failures = 0;

#define CHECK(cond)                                               \
  do {                                                            \
    if (!(cond)) {                                                \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
      failures++;                                                 \
    }                                                             \
  } while (0)

static void testVaxVector() {
  // tests/test_hmac_vector.py: key 00..1f, fixed vaccine, expected signature from openssl.
  uint8_t key[32];
  CHECK(hive::hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32));
  char canon[300];
  int n = hive::canonicalVax(canon, sizeof canon, "esp32", 7, "10.42.0.66", 300, "flood");
  CHECK(n > 0);
  CHECK(std::strcmp(canon,
                    "{\"issuer\":\"esp32\",\"reason\":\"flood\",\"rule\":\"block\",\"seq\":7,"
                    "\"t\":\"vax\",\"target\":\"10.42.0.66\",\"ttl\":300,\"v\":1}") == 0);
  char sig[65];
  CHECK(hive::signHex(key, canon, (size_t)n, sig));
  CHECK(std::strcmp(sig, "f55b1d5eafed736fb46a49608ae74ffc905b430902a3c73d3b3df59c226b1700") == 0);
  CHECK(hive::sigEquals(sig, "f55b1d5eafed736fb46a49608ae74ffc905b430902a3c73d3b3df59c226b1700"));
  CHECK(!hive::sigEquals(sig, "f55b1d5eafed736fb46a49608ae74ffc905b430902a3c73d3b3df59c226b1701"));
}

static void testEdgeVaxVector() {
  // Largest allowed seq, longest reason, max TTL: computed with agent/hive_core.py.
  uint8_t key[32];
  CHECK(hive::hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", key, 32));
  char canon[300], sig[65];
  int n = hive::canonicalVax(canon, sizeof canon, "lapB", 2147483647UL, "255.255.255.0", 600, "unknown_sender");
  CHECK(n > 0 && hive::signHex(key, canon, (size_t)n, sig));
  CHECK(std::strcmp(sig, "ed2c8ccae243da17e71bad311863706b75c2f5225fb6214c569292ca32de1581") == 0);
}

static void testCtrlVector() {
  uint8_t key[32];
  CHECK(hive::hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key, 32));
  char canon[120], sig[65];
  int n = hive::canonicalCtrl(canon, sizeof canon, "reset", 1791043200123ULL);
  CHECK(std::strcmp(canon, "{\"cmd\":\"reset\",\"seq\":1791043200123,\"t\":\"ctrl\",\"v\":1}") == 0);
  CHECK(n > 0 && hive::signHex(key, canon, (size_t)n, sig));
  CHECK(std::strcmp(sig, "2144d9017ee62251d7afe69bafa0609b16c1e9653dffedd375f220db84f2b97f") == 0);
}

static void testIPv4() {
  uint32_t ip = 0;
  CHECK(hive::parseIPv4("10.42.0.66", &ip));
  CHECK(ip == (10u | (42u << 8) | (0u << 16) | (66u << 24)));
  char text[16];
  hive::formatIPv4(ip, text);
  CHECK(std::strcmp(text, "10.42.0.66") == 0);
  CHECK(hive::parseIPv4("255.255.255.255", &ip) && ip == 0xffffffffu);
  CHECK(hive::parseIPv4("0.0.0.0", &ip) && ip == 0);
  const char* bad[] = {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.4 ", " 1.2.3.4",
                       "1..2.3", "1.2.3.-4", "a.b.c.d", "1.2.3.4.", "1234.1.1.1"};
  for (const char* s : bad) {
    if (hive::parseIPv4(s, &ip)) {
      std::printf("FAIL accepted bad ip '%s'\n", s);
      failures++;
    }
  }
}

static void testNodeIdAndHex() {
  CHECK(hive::validNodeId("esp32"));
  CHECK(hive::validNodeId("lap_B-2"));
  CHECK(!hive::validNodeId(""));
  CHECK(!hive::validNodeId("a b"));
  CHECK(!hive::validNodeId("abcdefghijklmnopq"));
  CHECK(!hive::validNodeId("x\"y"));
  uint8_t b[2];
  CHECK(!hive::hexToBytes("zz00", b, 2));
  CHECK(!hive::hexToBytes("000", b, 2));
  char num[21];
  hive::u64ToDec(0, num);
  CHECK(std::strcmp(num, "0") == 0);
  hive::u64ToDec(18446744073709551615ULL, num);
  CHECK(std::strcmp(num, "18446744073709551615") == 0);
}

int main() {
  testVaxVector();
  testEdgeVaxVector();
  testCtrlVector();
  testIPv4();
  testNodeIdAndHex();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("hive_sign.h: all host tests passed\n");
  return 0;
}
