// Template for secrets.h. Do not edit by hand: generate the real file with
//   python tools/provision_keys.py --ssid <SSID> --password <PASSWORD> [--led-pin 2]
// which fills in this node's key, every issuer's key and the shared tunables.
// secrets.h is gitignored; this example is committed so the layout is documented.
#pragma once

#define WIFI_SSID "HiveNet"
#define WIFI_PASS "change-me-please"

#define NODE_ID "esp32"
#define NODE_KEY_HEX "<64 hex chars>"
#define ADMIN_KEY_HEX "<64 hex chars>"

#define DATA_PORT 47000
#define VAX_PORT 47001
#define STATUS_PORT 47002
#define BROADCAST_IP "255.255.255.255"
#define HUB_IP ""        // "" = learn from the first hub command
#define DASHBOARD_IP ""  // "" = same as hub

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
  {"lapA", "<64 hex chars>"},
  {"lapB", "<64 hex chars>"},
  {"gateway", "<64 hex chars>"},
  {"rogue", "<64 hex chars>"},
};
static const int N_ISSUERS = sizeof(ISSUERS) / sizeof(ISSUERS[0]);
