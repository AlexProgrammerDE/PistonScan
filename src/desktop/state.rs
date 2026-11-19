use std::net::Ipv4Addr;

use pistonscan::{snapshot::HostResult, targets::Targets};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Filter {
    All,
    #[default]
    Online,
    Services,
    Identified,
}

impl Filter {
    pub(crate) fn matches(self, host: &HostResult) -> bool {
        match self {
            Self::All => true,
            Self::Online => host.reachable,
            Self::Services => !host.services.is_empty(),
            Self::Identified => name(host) != "Unknown device",
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Sort {
    #[default]
    Address,
    Name,
    Latency,
}

impl Sort {
    pub(crate) fn order(self, a: &HostResult, b: &HostResult) -> std::cmp::Ordering {
        let address = || {
            a.ip.parse::<Ipv4Addr>()
                .ok()
                .cmp(&b.ip.parse().ok())
                .then_with(|| a.ip.cmp(&b.ip))
        };
        match self {
            Self::Address => address(),
            Self::Name => name(a).cmp(name(b)).then_with(address),
            Self::Latency => b
                .reachable
                .cmp(&a.reachable)
                .then_with(|| a.latency_ms.total_cmp(&b.latency_ms))
                .then_with(address),
        }
    }
}

pub(crate) fn name(host: &HostResult) -> &str {
    std::iter::once(&host.device_name)
        .chain(&host.hostnames)
        .chain(&host.mdns_names)
        .chain(&host.netbios_names)
        .find(|name| !name.is_empty() && !name.eq_ignore_ascii_case("unknown"))
        .map_or("Unknown device", String::as_str)
}

pub(crate) fn matches(host: &HostResult, query: &str) -> bool {
    query.split_whitespace().all(|word| {
        [
            &host.ip,
            &host.mac_address,
            &host.manufacturer,
            &host.device_name,
            &host.os_guess,
        ]
        .into_iter()
        .chain(&host.hostnames)
        .chain(&host.mdns_names)
        .chain(&host.netbios_names)
        .chain(&host.llmnr_names)
        .chain(host.services.iter().map(|service| &service.service))
        .any(|value| value.to_lowercase().contains(word))
            || host
                .services
                .iter()
                .any(|service| service.port.to_string() == word)
    })
}

pub(crate) fn selected_row(
    hosts: &[HostResult],
    visible: &[usize],
    selected: &str,
) -> Option<usize> {
    visible
        .iter()
        .position(|index| hosts[*index].ip == selected)
}

pub(crate) fn target_count(target: &str) -> Result<u64, &'static str> {
    let count = Targets::parse(target)
        .map_err(|_error| "Enter an IPv4 address or subnet, such as 192.168.1.0/24.")?
        .count();
    if count > 65_536 {
        return Err("Choose a /16 or smaller subnet, or enter one IPv4 address.");
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::{Filter, Sort, matches, selected_row, target_count};
    use pistonscan::snapshot::{HostResult, ServiceInfo};

    #[test]
    fn search_combines_device_and_service_fields() {
        let host = HostResult {
            ip: "192.0.2.10".into(),
            manufacturer: "Synology".into(),
            services: vec![ServiceInfo {
                service: "HTTPS".into(),
                port: 5001,
                ..ServiceInfo::default()
            }],
            ..HostResult::default()
        };
        assert!(
            matches(&host, "synology https 5001"),
            "Search should combine fields"
        );
        assert!(
            !matches(&host, "synology ssh"),
            "Every search term must match"
        );
        assert!(
            Filter::Services.matches(&host),
            "Imported services can be filtered independently"
        );
        assert!(
            !Filter::Online.matches(&host),
            "Offline hosts are excluded from Online"
        );
    }

    #[test]
    fn address_order_is_numeric() {
        let a = HostResult {
            ip: "192.0.2.2".into(),
            ..HostResult::default()
        };
        let b = HostResult {
            ip: "192.0.2.10".into(),
            ..HostResult::default()
        };
        assert!(
            Sort::Address.order(&a, &b).is_lt(),
            "Sort addresses by octet"
        );
    }

    #[test]
    fn selection_follows_the_ip_when_a_streamed_host_sorts_earlier() {
        let mut hosts = vec![HostResult {
            ip: "192.0.2.10".into(),
            ..HostResult::default()
        }];
        let mut visible = vec![0];
        let selected = hosts[0].ip.clone();
        assert_eq!(
            selected_row(&hosts, &visible, &selected),
            Some(0),
            "Select the existing host"
        );
        hosts.push(HostResult {
            ip: "192.0.2.2".into(),
            ..HostResult::default()
        });
        visible.push(1);
        visible.sort_by(|a, b| Sort::Address.order(&hosts[*a], &hosts[*b]));
        assert_eq!(
            selected_row(&hosts, &visible, &selected),
            Some(1),
            "Keep the selected address as new hosts arrive"
        );
    }

    #[test]
    fn only_bounded_ipv4_targets_are_accepted() {
        assert_eq!(target_count("192.0.2.1"), Ok(1), "Accept a single IP");
        assert_eq!(target_count("192.0.2.99/16"), Ok(65_536), "Accept a /16");
        assert!(
            target_count("192.0.2.0/15").is_err(),
            "Reject larger targets"
        );
        assert!(target_count("localhost").is_err(), "Require IPv4");
    }
}
