# hc-sr04

`no_std`, platform-agnostic driver for the **HC-SR04 ultrasonic distance sensor**, built on `embedded-hal` 1.0.

```rust
use hc_sr04::HcSr04;

let mut sensor = HcSr04::new(trig_pin, echo_pin, delay);
match sensor.measure_cm() {
    Ok(cm)  => defmt::info!("distance = {} cm", cm),
    Err(e)  => defmt::warn!("sensor error: {:?}", e),
}
```

## Why another HC-SR04 crate?

Existing ones either target `embedded-hal` 0.2, depend on Cortex-M timers, or assume a free-running microsecond clock you can query. This crate uses only **`OutputPin`**, **`InputPin`**, and **`DelayNs`** — the smallest possible trait surface — and it busy-polls the delay source as its clock. That means it runs on **AVR** (Arduino Nano, Uno) where there is no `embedded_hal::time::Clock`, on Cortex-M, on ESP32, and on RP2040 alike.

## License

MIT OR Apache-2.0.
