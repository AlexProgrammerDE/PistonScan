use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

use tokio::process::Command;

static VENDORS: LazyLock<BTreeMap<&str, &str>> = LazyLock::new(|| {
    include_str!("../assets/oui/vendors.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect()
});

pub async fn lookup(ip: Ipv4Addr) -> String {
    let address = ip.to_string();
    if cfg!(target_os = "linux")
        && let Ok(table) = tokio::fs::read_to_string("/proc/net/arp").await
        && let Some(mac) = table.lines().find_map(|line| arp_entry(line, &address))
    {
        return mac;
    }
    let flag = if cfg!(windows) { "-a" } else { "-n" };
    let mut command = Command::new("arp");
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    command.arg(flag).arg(&address).kill_on_drop(true);
    let Ok(Ok(output)) =
        tokio::time::timeout(std::time::Duration::from_secs(4), command.output()).await
    else {
        return String::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| arp_entry(line, &address))
        .unwrap_or_default()
}

fn arp_entry(line: &str, address: &str) -> Option<String> {
    line.split_whitespace()
        .any(|word| word.trim_matches(['(', ')']) == address)
        .then(|| line.split_whitespace().find_map(normalize))
        .flatten()
}

fn normalize(text: &str) -> Option<String> {
    let bytes = text
        .split([':', '-'])
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let [first, second, third, fourth, fifth, sixth] = bytes.as_slice() else {
        return None;
    };
    if bytes.iter().all(|&byte| byte == 0) {
        return None;
    }
    Some(format!(
        "{first:02X}:{second:02X}:{third:02X}:{fourth:02X}:{fifth:02X}:{sixth:02X}"
    ))
}

#[must_use]
pub fn manufacturer(mac: &str) -> &'static str {
    if mac.is_empty() {
        return "";
    }
    let prefix = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(6)
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>();
    VENDORS.get(prefix.as_str()).copied().unwrap_or("Unknown")
}

#[cfg(test)]
mod tests {
    use super::{arp_entry, manufacturer};

    #[test]
    fn handles_neighbor_cache_and_vendor_prefix() {
        let mac = arp_entry("? (192.0.2.1) at 0:0:1:2:3:4 on en0", "192.0.2.1");
        assert_eq!(
            mac.as_deref(),
            Some("00:00:01:02:03:04"),
            "Normalize macOS ARP output"
        );
        assert_eq!(
            manufacturer("00-00-01-02-03-04"),
            "XEROX",
            "Look up the first 24 bits"
        );
        assert_eq!(
            manufacturer("FF:FF:FF:FF:FF:FF"),
            "Unknown",
            "Missing vendor"
        );
        assert_eq!(manufacturer(""), "", "Missing address");
    }
}
