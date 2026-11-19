#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `services::udp_exchange` receives datagrams into a 2048-byte buffer.
    if data.len() > 2048 {
        return;
    }
    let _ssdp = pistonscan::fuzzing::ssdp(data);
    let _snmp = pistonscan::fuzzing::snmp(data);
});
