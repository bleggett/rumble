extern crate rand;
extern crate rumble;

use rand::{thread_rng, Rng};
use rumble::api::{Central, UUID};
use rumble::bluez::manager::Manager;
use std::thread;
use std::time::Duration;

pub fn main() {
    let manager = Manager::new().unwrap();

    // get the first bluetooth adapter
    let adapters = manager.adapters().unwrap();
    let mut adapter = adapters.into_iter().nth(0).unwrap();

    // reset the adapter -- clears out any errant state
    adapter = manager.down(&adapter).unwrap();
    adapter = manager.up(&adapter).unwrap();

    // connect to the adapter
    let central = adapter.connect().unwrap();

    // start scanning for devices
    central.start_scan().unwrap();
    // instead of waiting, you can use central.on_event to be notified of
    // new devices
    thread::sleep(Duration::from_secs(2));

    // find the device we're interested in
    let light = central
        .peripherals()
        .into_iter()
        .find(|p| p.local_name.as_ref().unwrap().contains("LEDBlue"))
        .unwrap();

    // connect to the device
    central.connect(light.address).unwrap();

    // discover characteristics
    central.discover_characteristics(light.address).unwrap();

    // find the characteristic we want
    let chars = light.characteristics;
    let cmd_char = chars.iter().find(|c| c.uuid == UUID::B16(0xFFE9)).unwrap();

    // dance party
    let mut rng = thread_rng();
    for _ in 0..20 {
        let color_cmd = vec![0x56, rng.gen(), rng.gen(), rng.gen(), 0x00, 0xF0, 0xAA];
        central
            .command(light.address, &cmd_char, &color_cmd)
            .unwrap();
        thread::sleep(Duration::from_millis(200));
    }
}
