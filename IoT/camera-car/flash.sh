#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-/dev/ttyUSB0}"

if [ ! -e "$PORT" ]; then
  echo "Serial port $PORT not found."
  echo "ESP32-CAM has no USB — connect a 3.3V FTDI/CP2102 adapter to U0R/U0T/GND, then hold IO0->GND, tap RST, release IO0."
  echo "Pass the right port: ./flash.sh /dev/ttyUSB1"
  exit 1
fi

cargo run --release -- --port "$PORT"
