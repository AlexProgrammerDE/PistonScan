use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::{process::Command, time::timeout};

use crate::snapshot::HostResult;

pub async fn collect(ip: Ipv4Addr) -> HostResult {
    let target = ip.to_string();
    let mut result = HostResult {
        ip: target.clone(),
        attempts: 3,
        ..HostResult::default()
    };
    let mut command = Command::new("ping");
    #[cfg(windows)]
    command
        .args(["-n", "3", "-w", "1000"])
        .creation_flags(0x0800_0000);
    #[cfg(not(windows))]
    command.args(["-n", "-c", "3"]).env("LC_ALL", "C");
    command.arg(target).kill_on_drop(true);
    match timeout(Duration::from_secs(6), command.output()).await {
        Ok(Ok(output)) => {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some((latency, ttl)) = parse_reply(line) {
                    result.latency_samples.push(latency);
                    result.ttl = ttl;
                } else if let Some(ttl) = parse_ttl(&line.to_ascii_lowercase()) {
                    result.ttl = ttl;
                }
            }
            result.reachable = result.ttl > 0 || (!cfg!(windows) && output.status.success());
            if !result.latency_samples.is_empty() {
                result.latency_ms = result.latency_samples.iter().sum::<f64>()
                    / f64::from(u32::try_from(result.latency_samples.len()).unwrap_or(u32::MAX));
            }
        }
        Ok(Err(error)) => result.error = error.to_string(),
        Err(_elapsed) => {}
    }
    if !result.reachable && result.error.is_empty() {
        result.error = "no response".into();
    }
    if result.reachable {
        let (services, (), mac, smb) = tokio::join!(
            crate::services::scan(ip),
            crate::names::discover(&mut result, ip),
            crate::mac::lookup(ip),
            crate::smb::discover(ip)
        );
        result.services = services;
        result.smb_info = smb;
        result.os_guess = crate::insights::guess_os(&result.services).to_owned();
        result.mac_address = mac;
        result.manufacturer = crate::mac::manufacturer(&result.mac_address).to_owned();
        if crate::airplay::should_query(&result.services) {
            result.air_play = timeout(Duration::from_secs(2), crate::airplay::fetch(ip))
                .await
                .unwrap_or_default();
        }
        let airplay_name = result.air_play.as_ref().and_then(|data| {
            ["name", "deviceName", "pi", "deviceid", "model"]
                .into_iter()
                .find_map(|key| data.fields.get(key))
        });
        result.device_name = result
            .mdns_names
            .first()
            .or(airplay_name)
            .or_else(|| {
                result
                    .smb_info
                    .as_ref()
                    .map(|info| &info.computer_name)
                    .filter(|name| !name.is_empty())
            })
            .or_else(|| result.netbios_names.first())
            .or_else(|| result.llmnr_names.first())
            .or_else(|| result.hostnames.first())
            .cloned()
            .unwrap_or_default();
    }
    crate::insights::enrich(&mut result);
    result
}

fn parse_reply(line: &str) -> Option<(f64, u64)> {
    let line = line.to_ascii_lowercase();
    let ttl = parse_ttl(&line)?;
    let (_, elapsed) = line
        .split_once("time=")
        .or_else(|| line.split_once("time<"))?;
    let number = elapsed.trim_start().trim_end_matches("ms").trim();
    let number = number.split_whitespace().next()?.trim_end_matches("ms");
    Some((number.parse().ok()?, ttl))
}

fn parse_ttl(line: &str) -> Option<u64> {
    line.split_once("ttl=")?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::parse_reply;

    #[test]
    fn parses_unix_and_windows_replies() {
        assert_eq!(
            parse_reply("64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.25 ms"),
            Some((0.25, 64)),
            "Linux reply"
        );
        assert_eq!(
            parse_reply("Reply from 192.0.2.1: bytes=32 time<1ms TTL=128"),
            Some((1.0, 128)),
            "Windows reply"
        );
        assert_eq!(
            parse_reply("Request timeout"),
            None,
            "Timeout is not a reply"
        );
    }
}
