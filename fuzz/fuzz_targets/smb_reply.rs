#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte picks the pipe. `smb::transact` asks for at most 4096 output bytes.
    let Some((&pipe, response)) = data.split_first() else {
        return;
    };
    if response.len() > 4096 {
        return;
    }
    let _info = pistonscan::fuzzing::smb_reply(response, pipe & 1 == 0);
});
