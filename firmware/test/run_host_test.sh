#!/bin/sh
# Build and run the firmware tests on a PC (Linux/WSL/macOS, g++ and OpenSSL headers).
#   1. test_sign.cpp      hive_sign.h against the shared HMAC vectors
#   2. test_firmware.cpp  the real hive_node.ino with mocked Wi-Fi/UDP/NVS
# The second needs ArduinoJson (header-only): set ARDUINOJSON_SRC to its src/ folder,
# e.g. ~/Arduino/libraries/ArduinoJson/src (default: the arduino-cli install on G:).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="${TMPDIR:-/tmp}"
AJ="${ARDUINOJSON_SRC:-/mnt/g/Tools/arduino-cli/user/libraries/ArduinoJson/src}"

g++ -std=c++17 -Wall -Wextra -Werror -o "$OUT/hive_test_sign" "$HERE/test_sign.cpp" -lcrypto
"$OUT/hive_test_sign"

if [ ! -f "$AJ/ArduinoJson.h" ]; then
    echo "skipping firmware harness: ArduinoJson not found at $AJ (set ARDUINOJSON_SRC)"
    exit 0
fi
g++ -std=c++17 -Wall -Wextra -Wno-unused-function -DHIVE_HOST_TEST \
    -I "$HERE/mock" -I "$HERE" -I "$AJ" \
    -o "$OUT/hive_test_firmware" "$HERE/test_firmware.cpp" -lcrypto
"$OUT/hive_test_firmware"
