# IoT

Two robotics firmware projects, both in Rust, both built from the same parts kit. Together they are the demo backbone of the robotics-workshop teacher-training course.

| Project | Board | What it shows | Difficulty |
|---|---|---|---|
| [`obstacle-bot/`](./obstacle-bot) | Arduino Nano | Autonomous obstacle avoidance using HC-SR04 + L298N + TT motors. Pure no_std Rust on `avr-hal`. | Beginner-friendly to teach. |
| [`camera-car/`](./camera-car) | ESP32-CAM (Hiwonder / AI-Thinker) | Wi-Fi access point, MJPEG live video, phone-driven RC car. Pure Rust on `esp-idf-svc` + `esp-camera-rs`. | Advanced. The "wow" finale. |

Each folder has its own toolchain pin and its own README — open them independently in your editor; do not try to share a `Cargo.lock` between them.

## Why two boards, one kit?

The Nano gives the workshop a reliable, repeatable autonomy demo that always works. The ESP32-CAM gives the workshop a *story* — "this is where you can go next" — and it doubles as the security-cam / monitoring demo if a customer wants something other than education.

## Why Rust?

User has explicitly chosen Rust as a learning path. The Nano firmware uses [`avr-hal`](https://github.com/Rahix/avr-hal) (Rust-Embedded community); the ESP32-CAM firmware uses Espressif's official Rust support stack via [`espup`](https://github.com/esp-rs/espup) and [`esp-idf-svc`](https://github.com/esp-rs/esp-idf-svc). Both are mainstream, both are still moving fast — pin your dependencies.
