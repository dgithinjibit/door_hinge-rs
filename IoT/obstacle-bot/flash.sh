#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-/dev/ttyUSB0}"

if [ ! -e "$PORT" ]; then
  echo "Serial port $PORT not found. Plug in the Nano, or pass an explicit port:"
  echo "  ./flash.sh /dev/ttyUSB1"
  exit 1
fi

export RAVEDUDE_PORT="$PORT"
cargo run --release -p obstacle-bot-firmware
