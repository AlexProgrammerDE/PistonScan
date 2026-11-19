#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte picks HTTP or plain banner parsing. `services::read_banner`
    // stops reading once it holds 8192 bytes, after at most one more 1024-byte read.
    let Some((&mode, banner)) = data.split_first() else {
        return;
    };
    if banner.len() > 8191 + 1024 {
        return;
    }
    let _banner = pistonscan::fuzzing::tcp_banner(banner, mode & 1 == 1);
});
