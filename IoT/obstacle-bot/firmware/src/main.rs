#![no_std]
#![no_main]

use panic_halt as _;

use arduino_hal::{
    delay::Delay,
    simple_pwm::{IntoPwmPin, Prescaler, Timer1Pwm},
};
use hc_sr04::HcSr04;
use l298n::{L298N, Motor};

const STOP_CM: u16 = 10;
const SLOW_CM: u16 = 25;

const FORWARD_SPEED: u8 = 200;
const SLOW_SPEED: u8 = 130;
const TURN_SPEED: u8 = 180;

const BACKUP_MS: u16 = 350;
const TURN_MS: u16 = 400;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    ufmt::uwriteln!(&mut serial, "obstacle-bot booting...").ok();

    let trig = pins.d7.into_output().downgrade();
    let echo = pins.d8.into_floating_input().downgrade();
    let mut sensor = HcSr04::new(trig, echo, Delay::new());

    let timer1 = Timer1Pwm::new(dp.TC1, Prescaler::Prescale64);
    let left = Motor::new(
        pins.d2.into_output().downgrade(),
        pins.d3.into_output().downgrade(),
        pins.d9.into_output().into_pwm(&timer1).downgrade(),
    );
    let right = Motor::new(
        pins.d4.into_output().downgrade(),
        pins.d5.into_output().downgrade(),
        pins.d10.into_output().into_pwm(&timer1).downgrade(),
    );
    let mut bot = L298N::new(left, right);
    bot.stop().ok();

    let mut turn_left_next = true;
    let mut tick: u16 = 0;
    let mut delay = Delay::new();

    loop {
        match sensor.measure_cm() {
            Ok(cm) if cm < STOP_CM => {
                bot.stop().ok();
                arduino_hal::delay_ms(80);
                bot.reverse(TURN_SPEED).ok();
                arduino_hal::delay_ms(BACKUP_MS as u32);
                if turn_left_next {
                    bot.pivot_left(TURN_SPEED).ok();
                } else {
                    bot.pivot_right(TURN_SPEED).ok();
                }
                arduino_hal::delay_ms(TURN_MS as u32);
                turn_left_next = !turn_left_next;
                bot.stop().ok();
                ufmt::uwriteln!(&mut serial, "tick={} dist={} action=escape", tick, cm).ok();
            }
            Ok(cm) if cm < SLOW_CM => {
                bot.forward(SLOW_SPEED).ok();
                ufmt::uwriteln!(&mut serial, "tick={} dist={} action=slow", tick, cm).ok();
            }
            Ok(cm) => {
                bot.forward(FORWARD_SPEED).ok();
                ufmt::uwriteln!(&mut serial, "tick={} dist={} action=go", tick, cm).ok();
            }
            Err(_) => {
                bot.forward(SLOW_SPEED).ok();
                ufmt::uwriteln!(&mut serial, "tick={} dist=??? action=slow", tick).ok();
            }
        }

        tick = tick.wrapping_add(1);
        let _ = &mut delay;
        arduino_hal::delay_ms(50);
    }
}
