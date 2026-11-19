use std::collections::BTreeSet;

use crate::snapshot::HostResult;

pub fn enrich(host: &mut HostResult) {
    let mut score = 0;
    let mut sources = BTreeSet::new();
    if host.reachable {
        score += 2 + u64::from(!host.latency_samples.is_empty()) + u64::from(host.ttl > 0);
        sources.insert("icmp".to_owned());
    }
    for (source, names, weight) in [
        ("dns", &host.hostnames, 1),
        ("mdns", &host.mdns_names, 2),
        ("netbios", &host.netbios_names, 1),
        ("llmnr", &host.llmnr_names, 1),
    ] {
        if !names.is_empty() {
            score += names.len() as u64 * weight;
            sources.insert(source.to_owned());
        }
    }
    if let Some(smb) = &host.smb_info {
        score += u64::from(!smb.computer_name.is_empty()) * 2 + u64::from(!smb.domain.is_empty());
        sources.insert("smb".to_owned());
    }
    score += u64::from(!host.device_name.is_empty());
    for (source, value, weight) in [
        ("arp", &host.mac_address, 2),
        ("oui", &host.manufacturer, 1),
        ("fingerprint", &host.os_guess, 1),
    ] {
        if !value.is_empty() && !value.eq_ignore_ascii_case("unknown") {
            score += weight;
            sources.insert(source.to_owned());
        }
    }
    for service in &host.services {
        let protocol = service.protocol.trim();
        sources.insert(if protocol.is_empty() {
            "tcp".to_owned()
        } else {
            protocol.to_ascii_lowercase()
        });
        score += 2;
        if !service.tls_cert_info.is_empty() {
            sources.insert("tls".to_owned());
            score += 1;
        }
    }
    if host
        .air_play
        .as_ref()
        .is_some_and(|info| !info.fields.is_empty())
    {
        score += 2;
        sources.insert("airplay".to_owned());
    }
    host.discovery_sources = sources.into_iter().collect();
    host.insight_score = score;
}

#[must_use]
pub fn guess_os(services: &[crate::snapshot::ServiceInfo]) -> &'static str {
    let mut scores = [
        ("Windows", 0),
        ("Linux / Unix", 0),
        ("Apple / macOS", 0),
        ("Network Infrastructure", 0),
        ("Printer / Scanner", 0),
    ];
    for service in services {
        for (index, points) in service_scores(service).into_iter().enumerate() {
            scores[index].1 += points;
        }
    }
    scores.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));
    if scores[0].1 >= 6 && scores[0].1 - scores[1].1 >= 3 {
        scores[0].0
    } else {
        "Unknown"
    }
}

fn service_scores(service: &crate::snapshot::ServiceInfo) -> [i32; 5] {
    let mut windows = 0;
    let mut linux = 0;
    let mut apple = 0;
    let mut network = 0;
    let mut printer = 0;
    let name = service.service.to_ascii_lowercase();
    let banner = service.banner.to_ascii_lowercase();
    let tcp = service.protocol.eq_ignore_ascii_case("tcp");
    match service.port {
        445 | 3389 if tcp => windows += 8,
        135 | 139 if tcp => windows += 6,
        137 | 138 | 3268 | 5355 => windows += 4,
        389 | 5357 | 5985 | 5986 | 1433 => windows += 3,
        548 | 7000 if tcp => apple += 8,
        5353 => apple += 2,
        22 if tcp => linux += 5,
        2049 | 3306 | 5432 => linux += 3,
        631 => {
            linux += 3;
            printer += 6;
        }
        515 | 9100 => printer += 8,
        161 | 162 => network += 5,
        1723 | 502 | 7547 | 8291 | 8728 | 8729 => network += 8,
        _ => {}
    }
    let includes = |text: &str, keywords: &[&str]| keywords.iter().any(|key| text.contains(key));
    windows += 4 * i32::from(includes(&name, &["smb", "ms rpc", "rdp", "winrm", "ldap"]));
    windows += 6 * i32::from(includes(&banner, &["microsoft", "windows"]));
    apple += 6 * i32::from(includes(&name, &["airplay", "afp"]));
    apple += 6 * i32::from(includes(&banner, &["apple", "mac os", "ios", "ipad"]));
    linux += 4 * i32::from(name.contains("ssh"));
    linux += 3 * i32::from(includes(&name, &["redis", "postgres", "mysql", "nfs"]));
    linux += 6 * i32::from(includes(
        &banner,
        &[
            "openssh", "linux", "ubuntu", "debian", "centos", "red hat", "synology", "qnap",
        ],
    ));
    linux += 3 * i32::from(banner.contains("samba"));
    let contains = |words: &[&str]| includes(&name, words) || includes(&banner, words);
    network += 6 * i32::from(contains(&[
        "cisco",
        "routeros",
        "mikrotik",
        "ubiquiti",
        "ubnt",
        "edgeos",
        "juniper",
        "aruba",
        "fortinet",
        "fortigate",
        "meraki",
        "tp-link",
        "tplink",
        "netgear",
        "d-link",
        "brocade",
        "ruckus",
        "palo alto",
        "pan-os",
        "sonicwall",
        "watchguard",
        "draytek",
    ]));
    network += 5 * i32::from(contains(&["router", "switch"]));
    network += 6 * i32::from(name.contains("winbox"));
    printer += 6 * i32::from(contains(&[
        "hp",
        "hewlett-packard",
        "jetdirect",
        "printer",
        "xerox",
        "ricoh",
        "kyocera",
        "konica",
        "minolta",
        "sharp",
        "lexmark",
        "brother",
        "canon",
        "epson",
        "oki",
        "sindoh",
        "bizhub",
    ]));
    [windows, linux, apple, network, printer]
}

#[cfg(test)]
mod tests {
    use super::{enrich, guess_os};
    use crate::snapshot::{HostResult, ServiceInfo, SmbInfo};

    #[test]
    fn identifies_os_and_scores_discovery_sources() {
        let services = vec![ServiceInfo {
            port: 445,
            protocol: "tcp".to_owned(),
            service: "SMB".to_owned(),
            ..ServiceInfo::default()
        }];
        let os = guess_os(&services);
        assert_eq!(os, "Windows", "Strong SMB signals identify Windows");
        let mut host = HostResult {
            reachable: true,
            ttl: 64,
            latency_samples: vec![0.5],
            services,
            os_guess: os.to_owned(),
            smb_info: Some(SmbInfo {
                computer_name: "PC".to_owned(),
                domain: "LAN".to_owned(),
                ..SmbInfo::default()
            }),
            ..HostResult::default()
        };
        enrich(&mut host);
        assert_eq!(
            host.insight_score, 10,
            "Sum ICMP, SMB, service, and fingerprint evidence"
        );
        assert_eq!(
            host.discovery_sources,
            ["fingerprint", "icmp", "smb", "tcp"],
            "Sort the distinct evidence sources"
        );
    }
}
