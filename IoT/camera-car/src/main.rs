use std::sync::{Arc, Mutex};

use anyhow::Result;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::{
        gpio::{AnyOutputPin, Output, PinDriver},
        peripherals::Peripherals,
    },
    http::{server::EspHttpServer, Method},
    io::Write as IoWrite,
    nvs::EspDefaultNvsPartition,
    wifi::{AccessPointConfiguration, AuthMethod, BlockingWifi, Configuration, EspWifi},
};
use esp_camera_rs::Camera;
use log::{info, warn};

const AP_SSID: &str = "camera-car";
const AP_PASSWORD: &str = "kenya2026";
const AP_CHANNEL: u8 = 6;

const INDEX_HTML: &str = include_str!("../web/index.html");

struct MotorPins<'d> {
    in1: PinDriver<'d, AnyOutputPin, Output>,
    in2: PinDriver<'d, AnyOutputPin, Output>,
    in3: PinDriver<'d, AnyOutputPin, Output>,
    in4: PinDriver<'d, AnyOutputPin, Output>,
}

#[derive(Clone, Copy, Debug)]
enum Drive {
    Stop,
    Forward,
    Reverse,
    Left,
    Right,
}

impl<'d> MotorPins<'d> {
    fn apply(&mut self, drive: Drive) -> Result<()> {
        let (a, b, c, d) = match drive {
            Drive::Stop => (false, false, false, false),
            Drive::Forward => (true, false, true, false),
            Drive::Reverse => (false, true, false, true),
            Drive::Left => (false, true, true, false),
            Drive::Right => (true, false, false, true),
        };
        self.in1.set_level(a.into())?;
        self.in2.set_level(b.into())?;
        self.in3.set_level(c.into())?;
        self.in4.set_level(d.into())?;
        Ok(())
    }
}

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("camera-car starting up");

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let camera = Camera::new(
        peripherals.pins.gpio32.into(),
        peripherals.pins.gpio0.into(),
        peripherals.pins.gpio26.into(),
        peripherals.pins.gpio27.into(),
        peripherals.pins.gpio5.into(),
        peripherals.pins.gpio18.into(),
        peripherals.pins.gpio19.into(),
        peripherals.pins.gpio21.into(),
        peripherals.pins.gpio36.into(),
        peripherals.pins.gpio39.into(),
        peripherals.pins.gpio34.into(),
        peripherals.pins.gpio35.into(),
        peripherals.pins.gpio25.into(),
        peripherals.pins.gpio23.into(),
        peripherals.pins.gpio22.into(),
    )?;
    let camera = Arc::new(camera);
    info!("camera initialized");

    let motors = MotorPins {
        in1: PinDriver::output(peripherals.pins.gpio12.into())?,
        in2: PinDriver::output(peripherals.pins.gpio13.into())?,
        in3: PinDriver::output(peripherals.pins.gpio14.into())?,
        in4: PinDriver::output(peripherals.pins.gpio15.into())?,
    };
    let motors = Arc::new(Mutex::new(motors));
    motors.lock().unwrap().apply(Drive::Stop)?;
    info!("motors ready (stopped)");

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs))?,
        sysloop,
    )?;
    wifi.set_configuration(&Configuration::AccessPoint(AccessPointConfiguration {
        ssid: AP_SSID.try_into().unwrap(),
        ssid_hidden: false,
        channel: AP_CHANNEL,
        auth_method: AuthMethod::WPA2Personal,
        password: AP_PASSWORD.try_into().unwrap(),
        max_connections: 4,
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.wait_netif_up()?;
    info!("AP up — SSID={} password={}", AP_SSID, AP_PASSWORD);
    info!("connect, then visit http://192.168.71.1/");

    let mut server = EspHttpServer::new(&Default::default())?;

    server.fn_handler("/", Method::Get, |req| {
        let mut resp = req.into_ok_response()?;
        resp.write_all(INDEX_HTML.as_bytes())?;
        Ok::<(), anyhow::Error>(())
    })?;

    {
        let camera = camera.clone();
        server.fn_handler("/stream", Method::Get, move |req| {
            let headers = [
                ("Content-Type", "multipart/x-mixed-replace; boundary=frame"),
                ("Cache-Control", "no-store"),
                ("Connection", "close"),
            ];
            let mut resp = req.into_response(200, Some("OK"), &headers)?;
            loop {
                let fb = match camera.get_framebuffer() {
                    Some(fb) => fb,
                    None => {
                        warn!("no framebuffer");
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                };
                let header = format!(
                    "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                    fb.data().len()
                );
                if resp.write_all(header.as_bytes()).is_err() {
                    break;
                }
                if resp.write_all(fb.data()).is_err() {
                    break;
                }
                if resp.write_all(b"\r\n").is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        })?;
    }

    for (path, drive) in [
        ("/drive/forward", Drive::Forward),
        ("/drive/reverse", Drive::Reverse),
        ("/drive/left", Drive::Left),
        ("/drive/right", Drive::Right),
        ("/drive/stop", Drive::Stop),
    ] {
        let motors = motors.clone();
        server.fn_handler(path, Method::Post, move |req| {
            motors.lock().unwrap().apply(drive)?;
            let mut resp = req.into_ok_response()?;
            resp.write_all(format!("{:?}\n", drive).as_bytes())?;
            Ok::<(), anyhow::Error>(())
        })?;
    }

    info!("HTTP server listening on :80");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        info!("alive");
    }
}
