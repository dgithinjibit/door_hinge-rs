# camera-car

Wi-Fi camera car firmware for the **ESP32-CAM** (original ESP32, AI-Thinker / Hiwonder carrier), written in pure Rust on top of `esp-idf-svc` and `esp-camera-rs`.

When flashed, the board:

1. Brings up its own Wi-Fi access point (`camera-car` / password `kenya2026`).
2. Serves a webpage at `http://192.168.71.1/` with a live MJPEG stream from the OV2640 camera.
3. Listens for `POST /drive/{forward,reverse,left,right,stop}` to drive the L298N motors.

The HTML page shows the video and gives on-screen `▲ ◀ ■ ▶ ▼` buttons. Touch-and-hold to drive, release to stop.

## Hardware

- **ESP32-CAM** module (AI-Thinker compatible — the Hiwonder carrier exposes the same pins).
- **L298N** motor driver, 2× TT motors, wheels, ball caster.
- Battery pack for the motors (6–12 V) **plus** a separate clean 5V (or 3.3V regulated) supply for the ESP32-CAM. The camera browns out badly on the same rail as the motors.
- USB-to-serial adapter (CP2102 / FTDI 3.3V) **for flashing only** — the ESP32-CAM has no USB built in.

## Pin map

The OV2640 camera occupies a *lot* of GPIOs. These four are what's left for motor control:

| L298N | ESP32-CAM GPIO |
|---|---|
| IN1 | 12 |
| IN2 | 13 |
| IN3 | 14 |
| IN4 | 15 |

The L298N ENA / ENB enable pins should be **jumpered to +5V** (full speed). PWM speed control is left out of v1 because most of these GPIOs are also boot-strapping pins and PWM here is fragile. You get "go" and "stop", which is enough for the demo.

GPIO 12 is a strapping pin — keep it disconnected at boot (the L298N IN pins are high-impedance until the ESP32 enables them, which is fine, but if you see boot loops, add a 10kΩ pull-down on GPIO 12).

## One-time toolchain setup

```bash
cargo install espup ldproxy espflash
espup install
. ~/export-esp.sh        # or add it to your ~/.bashrc
# system packages for esp-idf
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-venv \
                    cmake ninja-build ccache libffi-dev libssl-dev dfu-util \
                    libusb-1.0-0 pkg-config
```

The first `cargo build` will download and build esp-idf v5.1.5 — expect 5–15 minutes and ~2 GB of disk. Subsequent builds are seconds.

## Flashing

The ESP32-CAM has no USB port. Wiring for flashing (one-time per dev cycle):

| FTDI/CP2102 | ESP32-CAM |
|---|---|
| GND  | GND |
| 5V   | 5V  |
| TX   | U0R |
| RX   | U0T |

To enter download mode: **short IO0 to GND**, tap RST, release IO0. Then:

```bash
. ~/export-esp.sh
./flash.sh                  # uses /dev/ttyUSB0
./flash.sh /dev/ttyUSB1     # override port
```

After flashing, press RST (no IO0 short this time) to boot the firmware. `espflash --monitor` will print logs.

## Using it

1. On your phone or laptop, join Wi-Fi `camera-car` with password `kenya2026`.
2. Open `http://192.168.71.1/` in a browser.
3. You should see the live stream and a directional pad.

## Workshop notes

This is the second hook demo, after the obstacle bot. The teaching beat: open the ESP32 serial monitor, show the boot logs, then have a trainee join the Wi-Fi from their own phone. The moment they steer the bot from their phone with live video, the workshop sells itself.

**Honest status:** this code has not yet been compiled on a real board. The `esp-camera-rs` crate is thin and the ESP32-CAM Rust ecosystem is rougher than mainline `esp-rs`. Expect the first build to surface 1–3 type mismatches between `esp-idf-svc` 0.52 and `esp-camera-rs`'s pinned older `esp-idf-hal`. When you hit them, paste the message and we'll patch.
