# obstacle-bot

Obstacle-avoiding robot for the **Arduino Nano**, written in Rust.

This is a Cargo workspace with three crates:

```
obstacle-bot/
├── crates/
│   ├── hc-sr04/      ← reusable HC-SR04 ultrasonic driver (embedded-hal 1.0)
│   └── l298n/        ← reusable L298N dual H-bridge driver (embedded-hal 1.0)
└── firmware/         ← the Arduino Nano binary that ties them together
```

## Why a workspace?

The two driver crates (`hc-sr04` and `l298n`) are deliberately **platform-agnostic** — they depend only on `embedded-hal` 1.0 traits, not on `arduino-hal`. That means the same code will work on an STM32, RP2040, or ESP32 the day you outgrow the Nano. They are also written to be publishable to crates.io if you want to make a real contribution to the Rust embedded ecosystem.

The `firmware/` crate is the Nano-specific glue: it picks pins, configures Timer1 for PWM, and runs the avoidance state machine using the two drivers.

## Hardware

- Arduino Nano (ATmega328P, old or new bootloader)
- L298N motor driver, 2× yellow TT gear motors + wheels + ball caster
- HC-SR04 ultrasonic sensor
- Battery pack for motors (6–12 V), separate from USB
- USB cable for flashing

### Wiring

| Component | Signal | Nano pin |
|---|---|---|
| HC-SR04 | TRIG | D7 |
| HC-SR04 | ECHO | D8 |
| L298N   | IN1  | D2 |
| L298N   | IN2  | D3 |
| L298N   | IN3  | D4 |
| L298N   | IN4  | D5 |
| L298N   | ENA (PWM) | D9 |
| L298N   | ENB (PWM) | D10 |

Power:
- HC-SR04 VCC → 5V, GND → GND.
- L298N logic VCC → 5V from Nano, motor VCC → battery pack +, GND tied to **both** Nano GND and battery GND.
- Remove the ENA/ENB jumpers on the L298N so the Nano can PWM them.

If the bot spins instead of going forward, swap the wires of **one** motor (or change `Direction::Forward` ↔ `Direction::Reverse` on one side in `firmware/src/main.rs`).

## Behaviour

Every ~50 ms, the bot pings the HC-SR04 and decides:

- `dist > 25 cm` → drive forward fast (`go`)
- `10 cm < dist ≤ 25 cm` → drive forward slow (`slow`)
- `dist ≤ 10 cm` or sensor error → stop, back up, pivot (alternating left/right to escape corners), then continue (`escape`)

Live status is printed at 57600 baud over the USB serial line. `ravedude` opens this console automatically after flashing.

## One-time toolchain setup

The `rust-toolchain.toml` pins the nightly compiler; `rustup` will install it on first build. System packages:

```bash
sudo apt install avr-libc gcc-avr avrdude pkg-config libudev-dev
cargo install ravedude
sudo usermod -a -G dialout "$USER"    # then log out + back in
```

## Build & flash

```bash
./flash.sh                    # uses /dev/ttyUSB0
./flash.sh /dev/ttyUSB1       # or override
```

If your Nano is the "old bootloader" variant, change `board = "nano"` to `board = "nano-old"` in `Ravedude.toml`.

## Workshop / video angle

Three things to highlight when filming:

1. **The drivers are not `arduino-hal`-specific.** Open `crates/hc-sr04/src/lib.rs` — the only imports are `embedded_hal::digital::{InputPin, OutputPin}` and `embedded_hal::delay::DelayNs`. Same code, different board, no changes.
2. **The HC-SR04 trick.** AVR has no monotonic clock you can query. Most existing HC-SR04 crates assume one. This one busy-polls a `DelayNs` source as its clock — which is exactly why it works on AVR where others don't.
3. **The L298N speed rescaling.** Every PWM peripheral has a different `max_duty_cycle`. The driver takes `u8` 0..=255 from the user and rescales to whatever the actual timer resolution is. The user never has to think about timer prescaler arithmetic.

If you publish the two driver crates to crates.io, mention this README in the description — that's the part that explains why they exist when there are already half-finished alternatives.
