// Fixed keys and tunables for the PC firmware harness (not used on hardware).
#pragma once

#define WIFI_SSID "test"
#define WIFI_PASS "test-password"

#define NODE_ID "esp32"
#define NODE_KEY_HEX "1111111111111111111111111111111111111111111111111111111111111111"
#define ADMIN_KEY_HEX "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

#define DATA_PORT 47000
#define VAX_PORT 47001
#define STATUS_PORT 47002
#define BROADCAST_IP "255.255.255.255"
#define HUB_IP ""
#define DASHBOARD_IP ""

#define LED_PIN 2
#define LED_ACTIVE_LOW 0

#define QUORUM 2
#define LEARN_SECONDS 20
#define WINDOW_MS 1000
#define THRESHOLD 6.0f
#define CONSECUTIVE 2
#define QUARANTINE_HOLD_S 30
#define VAX_TTL_S 300
#define VAX_RATE_MAX_PER_MIN 3
#define DISTRUST_S 300
#define PENDING_S 120

struct IssuerKey { const char* id; const char* key_hex; };
static const IssuerKey ISSUERS[] = {
  {"lapA", "2222222222222222222222222222222222222222222222222222222222222222"},
  {"lapB", "3333333333333333333333333333333333333333333333333333333333333333"},
  {"gateway", "4444444444444444444444444444444444444444444444444444444444444444"},
  {"rogue", "5555555555555555555555555555555555555555555555555555555555555555"},
};
static const int N_ISSUERS = sizeof(ISSUERS) / sizeof(ISSUERS[0]);
