#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `names::netbios_names` receives the reply into a 4096-byte buffer.
    if data.len() > 4096 {
        return;
    }
    let _names = pistonscan::fuzzing::netbios_status(data);
});
