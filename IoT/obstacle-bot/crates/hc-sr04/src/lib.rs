#![no_std]
#![doc = include_str!("../README.md")]

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{InputPin, OutputPin};

/// Speed of sound at 20°C: ~343 m/s. The echo travels there and back, so
/// 1 cm of round-trip distance ≈ 58 µs of high pulse on ECHO.
pub const US_PER_CM: u32 = 58;

/// Maximum sensible round-trip time, in microseconds. Beyond this the reading
/// is treated as out-of-range (or a missing target). Corresponds to ~4.3 m.
pub const DEFAULT_TIMEOUT_US: u32 = 25_000;

/// Trigger pulse width per the datasheet: at least 10 µs HIGH.
pub const TRIG_PULSE_US: u32 = 10;

/// Errors returned by [`HcSr04::measure_cm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<TE, EE> {
    /// The TRIG output pin returned an error.
    Trig(TE),
    /// The ECHO input pin returned an error.
    Echo(EE),
    /// Sensor did not respond within the configured timeout. Usually means
    /// the target is out of range or the wiring is wrong.
    Timeout,
    /// Reading was nonsensical (≤ 0 cm or > 400 cm).
    OutOfRange,
}

/// Driver for the HC-SR04 ultrasonic distance sensor.
///
/// Generic over the TRIG output pin, the ECHO input pin, and a microsecond
/// delay source — usually the HAL's `Delay` type. The delay source is also
/// used as a busy-poll clock to measure the ECHO pulse width, which is what
/// makes this crate work on platforms (like AVR) that have no monotonic
/// hardware timer to query.
pub struct HcSr04<TRIG, ECHO, DELAY> {
    trig: TRIG,
    echo: ECHO,
    delay: DELAY,
    timeout_us: u32,
}

impl<TRIG, ECHO, DELAY, TE, EE> HcSr04<TRIG, ECHO, DELAY>
where
    TRIG: OutputPin<Error = TE>,
    ECHO: InputPin<Error = EE>,
    DELAY: DelayNs,
{
    /// Create a new driver. Takes ownership of the pins and a delay source.
    pub fn new(trig: TRIG, echo: ECHO, delay: DELAY) -> Self {
        Self {
            trig,
            echo,
            delay,
            timeout_us: DEFAULT_TIMEOUT_US,
        }
    }

    /// Override the echo-wait timeout. Default is [`DEFAULT_TIMEOUT_US`].
    pub fn with_timeout_us(mut self, timeout_us: u32) -> Self {
        self.timeout_us = timeout_us;
        self
    }

    /// Release the underlying resources.
    pub fn release(self) -> (TRIG, ECHO, DELAY) {
        (self.trig, self.echo, self.delay)
    }

    /// Take a distance reading in centimetres.
    ///
    /// Blocks for up to `timeout_us` waiting for the ECHO pulse to rise, then
    /// for up to `timeout_us` more measuring its width.
    pub fn measure_cm(&mut self) -> Result<u16, Error<TE, EE>> {
        self.trig.set_low().map_err(Error::Trig)?;
        self.delay.delay_us(2);
        self.trig.set_high().map_err(Error::Trig)?;
        self.delay.delay_us(TRIG_PULSE_US);
        self.trig.set_low().map_err(Error::Trig)?;

        let mut waited = 0u32;
        while self.echo.is_low().map_err(Error::Echo)? {
            if waited >= self.timeout_us {
                return Err(Error::Timeout);
            }
            self.delay.delay_us(1);
            waited += 1;
        }

        let mut high_us = 0u32;
        while self.echo.is_high().map_err(Error::Echo)? {
            if high_us >= self.timeout_us {
                return Err(Error::Timeout);
            }
            self.delay.delay_us(1);
            high_us += 1;
        }

        let cm = high_us / US_PER_CM;
        if cm == 0 || cm > 400 {
            Err(Error::OutOfRange)
        } else {
            Ok(cm as u16)
        }
    }
}
