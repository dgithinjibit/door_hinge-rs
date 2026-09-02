# l298n

`no_std`, platform-agnostic driver for the **L298N dual H-bridge motor driver**, built on `embedded-hal` 1.0.

```rust
use l298n::{L298N, Motor};

let left  = Motor::new(in1, in2, ena_pwm);
let right = Motor::new(in3, in4, enb_pwm);
let mut bot = L298N::new(left, right);

bot.forward(200)?;
bot.pivot_left(180)?;
bot.stop()?;
```

## Why another L298N crate?

Existing crates on crates.io are tied to specific HALs (RP2040, STM32F1, etc.) or use `embedded-hal` 0.2. This crate is generic over **any** `OutputPin` and **any** `SetDutyCycle` (PWM) pin and so works on AVR (Arduino Nano), Cortex-M, ESP32, and RP2040 alike. Speed is a `u8` (0..=255) and is rescaled internally to the PWM peripheral's actual `max_duty_cycle`, so you don't need to know your timer's resolution.

## License

MIT OR Apache-2.0.
