#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The peer certificate comes from the TLS handshake without a size limit of its own.
    let _summary = pistonscan::fuzzing::tls_summary(data);
});
