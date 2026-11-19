use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::{net::UdpSocket, task::spawn_blocking, time::timeout};

use crate::snapshot::HostResult;

pub async fn discover(host: &mut HostResult, ip: Ipv4Addr) {
    let (dns, llmnr, netbios, mdns) = tokio::join!(
        reverse_dns(ip),
        llmnr_names(ip),
        netbios_names(ip),
        mdns_names(ip),
    );
    host.hostnames = dns;
    host.llmnr_names = llmnr;
    host.netbios_names = netbios;
    host.mdns_names = mdns;
}

async fn reverse_dns(ip: Ipv4Addr) -> Vec<String> {
    let lookup = spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)));
    match timeout(Duration::from_secs(4), lookup).await {
        Ok(Ok(Ok(name))) if name.trim_end_matches('.') != ip.to_string() => {
            vec![name.trim_end_matches('.').to_owned()]
        }
        _ => Vec::new(),
    }
}

async fn llmnr_names(ip: Ipv4Addr) -> Vec<String> {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return Vec::new();
    };
    let mut query = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ip.octets().iter().rev().map(u8::to_string) {
        query.push(u8::try_from(label.len()).unwrap_or(0));
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(b"\x07in-addr\x04arpa\x00\x00\x0c\x00\x01");
    let _multicast = socket
        .send_to(&query, (Ipv4Addr::new(224, 0, 0, 252), 5355))
        .await;
    let _unicast = socket.send_to(&query, (ip, 5355)).await;
    let mut names = BTreeSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut buffer = [0; 512];
    while let Ok(Ok((length, sender))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        if sender.ip() == IpAddr::V4(ip) {
            names.extend(parse_ptr(&buffer[..length]));
            if names.len() >= 5 {
                break;
            }
        }
    }
    names.into_iter().collect()
}

pub(crate) fn parse_ptr(packet: &[u8]) -> Vec<String> {
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::RData;

    let Ok(msg) = Message::from_vec(packet) else {
        return Vec::new();
    };
    if msg.id != 1 || msg.message_type != MessageType::Response {
        return Vec::new();
    }
    msg.answers
        .iter()
        .filter_map(|record| {
            let RData::PTR(name) = &record.data else {
                return None;
            };
            let text = name.to_utf8();
            let text = text.trim_end_matches('.');
            let text = text
                .strip_suffix(".local")
                .or_else(|| text.strip_suffix(".in-addr.arpa"))
                .unwrap_or(text);
            (!text.is_empty()).then(|| text.to_owned())
        })
        .collect()
}

async fn netbios_names(ip: Ipv4Addr) -> Vec<String> {
    let mut query = [b'A'; 50];
    query[..15].copy_from_slice(&[0x82, 0x28, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, b'C', b'K']);
    query[45..].copy_from_slice(&[0, 0, 0x21, 0, 1]);
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return Vec::new();
    };
    if socket.connect((ip, 137)).await.is_err() || socket.send(&query).await.is_err() {
        return Vec::new();
    }
    let mut buffer = [0; 4096];
    match timeout(Duration::from_secs(4), socket.recv(&mut buffer)).await {
        Ok(Ok(length)) => parse_nbstat(&buffer[..length]),
        _ => Vec::new(),
    }
}

pub(crate) fn parse_nbstat(packet: &[u8]) -> Vec<String> {
    if !matches!(packet, [0x82, 0x28, flags, ..] if flags & 0x80 != 0) {
        return Vec::new();
    }
    let Some([_, _, _, _, _, questions, 0, answers, ..]) = packet.get(..12) else {
        return Vec::new();
    };
    if *answers == 0 {
        return Vec::new();
    }
    let mut offset = 12;
    for _ in 0..*questions {
        let Some(end) = skip_name(packet, offset) else {
            return Vec::new();
        };
        offset = end + 4;
    }
    let Some(end) = skip_name(packet, offset) else {
        return Vec::new();
    };
    let Some([0, 0x21, _, _, _, _, _, _, high, low, ..]) = packet.get(end..) else {
        return Vec::new();
    };
    let length = usize::from(u16::from_be_bytes([*high, *low]));
    let Some([count, names @ ..]) = packet.get(end + 10..end + 10 + length) else {
        return Vec::new();
    };
    let names = names
        .as_chunks::<18>()
        .0
        .iter()
        .take(usize::from(*count))
        .filter_map(|entry| {
            let name = std::str::from_utf8(&entry[..15]).ok()?.trim();
            let flags = u16::from_be_bytes([entry[16], entry[17]]);
            (flags & 0x8000 != 0 && matches!(entry[15], 0 | 3 | 0x20) && !name.is_empty())
                .then(|| name.to_owned())
        })
        .collect::<BTreeSet<_>>();
    names.into_iter().collect()
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)?;
        match length {
            0 => return Some(offset + 1),
            192..=255 => return packet.get(offset + 1).map(|_| offset + 2),
            1..=63 => offset += usize::from(length) + 1,
            _ => return None,
        }
    }
}

const SERVICE_TYPES: &[&str] = &[
    "_services._dns-sd._udp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ftp._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_companion-link._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_rdp._tcp.local.",
    "_rfb._tcp.local.",
    "_telnet._tcp.local.",
    "_nfs._tcp.local.",
    "_webdav._tcp.local.",
    "_daap._tcp.local.",
    "_dpap._tcp.local.",
    "_dacp._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
];

struct MdnsDaemon(mdns_sd::ServiceDaemon);

impl Drop for MdnsDaemon {
    fn drop(&mut self) {
        let _shutdown = self.0.shutdown();
    }
}

async fn mdns_names(ip: Ipv4Addr) -> Vec<String> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};

    let Ok(daemon) = ServiceDaemon::new() else {
        return Vec::new();
    };
    let daemon = MdnsDaemon(daemon);
    let mut tasks = tokio::task::JoinSet::new();
    for service in SERVICE_TYPES {
        if let Ok(events) = daemon.0.browse(service) {
            tasks.spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                let mut names = BTreeSet::new();
                while let Ok(Ok(event)) =
                    tokio::time::timeout_at(deadline, events.recv_async()).await
                {
                    if let ServiceEvent::ServiceResolved(info) = event
                        && info
                            .get_addresses()
                            .iter()
                            .any(|address| address.to_string() == ip.to_string())
                    {
                        names.insert(info.get_hostname().trim_end_matches('.').to_owned());
                        names.insert(service.trim_end_matches(".local.").to_owned());
                        if let Some(instance) = info.get_fullname().strip_suffix(service) {
                            names.insert(instance.trim_end_matches('.').to_owned());
                        }
                        for key in ["fn", "id", "model", "name", "md"] {
                            if let Some(value) = info.get_property_val_str(key) {
                                names.insert(value.trim().to_owned());
                            }
                        }
                    }
                }
                names
            });
        }
    }
    let mut names = BTreeSet::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(result) = result {
            names.extend(result);
        }
    }
    names.remove("");
    names.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_nbstat, parse_ptr};

    #[test]
    fn parses_node_status_with_no_question() {
        let mut reply = vec![0x82, 0x28, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        reply.extend_from_slice(&[0, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 19, 1]);
        reply.extend_from_slice(b"WORKSTATION    ");
        reply.extend_from_slice(&[0, 0x80, 0]);
        assert_eq!(
            parse_nbstat(&reply),
            ["WORKSTATION"],
            "Decode the active workstation name"
        );
        reply.pop();
        assert!(parse_nbstat(&reply).is_empty(), "Reject a truncated record");
    }

    #[test]
    fn parses_reverse_ptr_answer() {
        let mut reply = vec![0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        reply.extend_from_slice(&[0, 0, 12, 0, 1, 0, 0, 0, 0, 0, 13]);
        reply.extend_from_slice(b"\x05piano\x05local\0");
        assert_eq!(parse_ptr(&reply), ["piano"], "Remove the local suffix");
        assert!(
            parse_ptr(&reply[..12]).is_empty(),
            "Reject a missing answer"
        );
    }
}
