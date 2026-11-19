#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `names::llmnr_names` receives replies into a 512-byte buffer.
    if data.len() > 512 {
        return;
    }
    let _names = pistonscan::fuzzing::llmnr_ptr(data);
});
