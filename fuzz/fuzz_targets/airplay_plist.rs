#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `airplay::fetch` stops reading a response body at 1 MiB.
    if data.len() > 1_048_576 {
        return;
    }
    let _fields = pistonscan::airplay::parse_response(data);
});
