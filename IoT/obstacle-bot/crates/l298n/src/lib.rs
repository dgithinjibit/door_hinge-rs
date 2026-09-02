#![no_std]
#![doc = include_str!("../README.md")]

use embedded_hal::digital::OutputPin;
use embedded_hal::pwm::SetDutyCycle;

/// Direction a single motor can be driven in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// IN1 high, IN2 low (or the side's equivalent).
    Forward,
    /// IN1 low, IN2 high.
    Reverse,
    /// Both inputs low → coast / brake depending on the L298N variant.
    Stop,
}

/// Which motor on the L298N a command refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Wired to OUT1 / OUT2, controlled by IN1 / IN2 / ENA.
    Left,
    /// Wired to OUT3 / OUT4, controlled by IN3 / IN4 / ENB.
    Right,
}

/// One side of an L298N: two direction pins and one enable/PWM pin.
pub struct Motor<IN_A, IN_B, EN> {
    in_a: IN_A,
    in_b: IN_B,
    en: EN,
}

impl<IN_A, IN_B, EN, PE> Motor<IN_A, IN_B, EN>
where
    IN_A: OutputPin,
    IN_B: OutputPin,
    EN: SetDutyCycle<Error = PE>,
{
    pub fn new(in_a: IN_A, in_b: IN_B, en: EN) -> Self {
        Self { in_a, in_b, en }
    }

    /// Drive in the given direction at the given speed (0..=255).
    ///
    /// `speed = 0` is treated the same as `Direction::Stop`.
    pub fn drive(&mut self, direction: Direction, speed: u8) -> Result<(), Error<PE>> {
        let (a, b) = match direction {
            Direction::Forward => (true, false),
            Direction::Reverse => (false, true),
            Direction::Stop => (false, false),
        };
        // OutputPin::set_high/set_low on infallible pins (the common case on
        // microcontroller HALs) return Result<(), Infallible>; we discard the
        // error type rather than thread it through the generics.
        let _ = if a { self.in_a.set_high() } else { self.in_a.set_low() };
        let _ = if b { self.in_b.set_high() } else { self.in_b.set_low() };

        let duty = if matches!(direction, Direction::Stop) {
            0
        } else {
            speed
        };
        let max = self.en.max_duty_cycle();
        let scaled = ((duty as u32 * max as u32) / 255) as u16;
        self.en.set_duty_cycle(scaled).map_err(Error::Pwm)
    }

    pub fn stop(&mut self) -> Result<(), Error<PE>> {
        self.drive(Direction::Stop, 0)
    }
}

/// Errors from a motor command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<PE> {
    Pwm(PE),
}

/// A complete L298N: a left motor and a right motor.
pub struct L298N<LA, LB, LE, RA, RB, RE> {
    left: Motor<LA, LB, LE>,
    right: Motor<RA, RB, RE>,
}

impl<LA, LB, LE, RA, RB, RE, PE> L298N<LA, LB, LE, RA, RB, RE>
where
    LA: OutputPin,
    LB: OutputPin,
    LE: SetDutyCycle<Error = PE>,
    RA: OutputPin,
    RB: OutputPin,
    RE: SetDutyCycle<Error = PE>,
{
    pub fn new(left: Motor<LA, LB, LE>, right: Motor<RA, RB, RE>) -> Self {
        Self { left, right }
    }

    pub fn set(&mut self, side: Side, direction: Direction, speed: u8) -> Result<(), Error<PE>> {
        match side {
            Side::Left => self.left.drive(direction, speed),
            Side::Right => self.right.drive(direction, speed),
        }
    }

    pub fn forward(&mut self, speed: u8) -> Result<(), Error<PE>> {
        self.left.drive(Direction::Forward, speed)?;
        self.right.drive(Direction::Forward, speed)
    }

    pub fn reverse(&mut self, speed: u8) -> Result<(), Error<PE>> {
        self.left.drive(Direction::Reverse, speed)?;
        self.right.drive(Direction::Reverse, speed)
    }

    pub fn pivot_left(&mut self, speed: u8) -> Result<(), Error<PE>> {
        self.left.drive(Direction::Reverse, speed)?;
        self.right.drive(Direction::Forward, speed)
    }

    pub fn pivot_right(&mut self, speed: u8) -> Result<(), Error<PE>> {
        self.left.drive(Direction::Forward, speed)?;
        self.right.drive(Direction::Reverse, speed)
    }

    pub fn stop(&mut self) -> Result<(), Error<PE>> {
        self.left.stop()?;
        self.right.stop()
    }
}
