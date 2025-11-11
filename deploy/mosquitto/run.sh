#!/usr/bin/env bash
set -euo pipefail

echo "|> Starting Mosquitto with ASan/UBSan/LSan + coverage"
echo "  - ASAN_OPTIONS=$ASAN_OPTIONS"
echo "  - UBSAN_OPTIONS=$UBSAN_OPTIONS"
echo "  - LLVM_PROFILE_FILE=$LLVM_PROFILE_FILE"

rm -f /mosquitto/data/*.profraw 2>/dev/null || true
# exec /usr/local/sbin/mosquitto -c /opt/mosquitto/mosquitto.conf -v
/opt/mosquitto/sbin/mosquitto -c /opt/mosquitto/mosquitto.conf 2> /mosquitto/log/mosquitto-stderr.log
