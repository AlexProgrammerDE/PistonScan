//! Parser entry points for the `fuzz/` crate.
//!
//! This module only exists in builds with `--cfg fuzzing`, which `cargo fuzz` sets.

use crate::snapshot::SmbInfo;

#[must_use]
pub fn llmnr_ptr(packet: &[u8]) -> Vec<String> {
    crate::names::parse_ptr(packet)
}

#[must_use]
pub fn netbios_status(packet: &[u8]) -> Vec<String> {
    crate::names::parse_nbstat(packet)
}

/// Decodes a level-100 RPC response from the `wkssvc` or `srvsvc` pipe.
#[must_use]
pub fn smb_reply(response: &[u8], workstation: bool) -> Option<SmbInfo> {
    let endpoint = if workstation {
        crate::smb::Endpoint::Workstation
    } else {
        crate::smb::Endpoint::Server
    };
    crate::smb::parse_reply(response, endpoint)
}

#[must_use]
pub fn tcp_banner(data: &[u8], http: bool) -> String {
    crate::services::parse_banner(data, http)
}

#[must_use]
pub fn ssdp(data: &[u8]) -> Option<String> {
    crate::services::parse_ssdp(data)
}

#[must_use]
pub fn snmp(data: &[u8]) -> Option<&'static str> {
    crate::services::parse_snmp(data)
}

#[must_use]
pub fn tls_summary(der: &[u8]) -> Option<String> {
    crate::tls::summarize(der)
}
