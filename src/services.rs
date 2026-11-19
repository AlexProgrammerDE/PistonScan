const TCP_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (81, "HTTP Alt"),
    (110, "POP3"),
    (135, "MS RPC"),
    (139, "NetBIOS Session"),
    (143, "IMAP"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (502, "Modbus/TCP"),
    (515, "LPD"),
    (587, "SMTP Submission"),
    (631, "IPP"),
    (636, "LDAPS"),
    (700, "EPP"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle DB"),
    (1723, "PPTP"),
    (1883, "MQTT"),
    (2049, "NFS"),
    (27017, "MongoDB"),
    (3000, "HTTP Dev"),
    (3128, "Squid Proxy"),
    (3268, "AD Global Catalog"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (4200, "Angular Dev"),
    (5000, "UPnP/WS"),
    (5432, "PostgreSQL"),
    (5601, "Kibana"),
    (5671, "AMQP TLS"),
    (5672, "AMQP"),
    (5900, "VNC"),
    (5984, "CouchDB"),
    (5985, "WinRM HTTP"),
    (5986, "WinRM HTTPS"),
    (6379, "Redis"),
    (7000, "AirPlay"),
    (7547, "TR-069"),
    (8000, "HTTP Dev"),
    (8001, "HTTP Dev"),
    (8002, "HTTP Dev"),
    (8003, "HTTP Dev"),
    (8004, "HTTP Dev"),
    (8005, "HTTP Dev"),
    (8006, "HTTP Dev"),
    (8007, "HTTP Dev"),
    (8008, "HTTP Dev"),
    (8009, "HTTP Dev"),
    (8010, "HTTP Dev"),
    (8080, "HTTP Alt"),
    (8081, "HTTP Alt"),
    (8082, "HTTP Alt"),
    (8083, "HTTP Alt"),
    (8086, "InfluxDB"),
    (8088, "HTTP Alt"),
    (8291, "MikroTik WinBox"),
    (8443, "HTTPS Alt"),
    (8530, "WSUS"),
    (8728, "MikroTik API"),
    (8729, "MikroTik API TLS"),
    (8888, "HTTP Alt"),
    (9000, "HTTP Alt"),
    (9042, "Cassandra"),
    (9100, "JetDirect"),
    (9200, "Elasticsearch"),
    (9443, "HTTPS Alt"),
    (11211, "Memcached"),
];
const UDP_PORTS: &[(u16, &str)] = &[
    (53, "DNS"),
    (67, "DHCP Server"),
    (68, "DHCP Client"),
    (69, "TFTP"),
    (123, "NTP"),
    (137, "NetBIOS Name"),
    (138, "NetBIOS Datagram"),
    (161, "SNMP"),
    (162, "SNMP Trap"),
    (500, "IKE/IPSec"),
    (514, "Syslog"),
    (520, "RIP"),
    (1900, "SSDP/UPnP"),
    (5353, "mDNS"),
    (5355, "LLMNR"),
];

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};

use crate::snapshot::ServiceInfo;

pub async fn scan(ip: Ipv4Addr) -> Vec<ServiceInfo> {
    let (mut tcp, udp) = tokio::join!(tcp_services(ip), udp_services(ip));
    tcp.extend(udp);
    tcp.sort_unstable_by(|a, b| (a.port, &a.protocol).cmp(&(b.port, &b.protocol)));
    tcp
}

async fn tcp_services(ip: Ipv4Addr) -> Vec<ServiceInfo> {
    let mut results = Vec::new();
    for ports in TCP_PORTS.chunks(32) {
        let mut probes = JoinSet::new();
        for &(port, name) in ports {
            probes.spawn(async move {
                let mut client =
                    timeout(Duration::from_millis(400), TcpStream::connect((ip, port)))
                        .await
                        .ok()?
                        .ok()?;
                let banner = timeout(
                    Duration::from_millis(300),
                    read_banner(&mut client, ip, port),
                )
                .await
                .unwrap_or_default();
                let tls_cert_info = if matches!(port, 443 | 5986 | 8443 | 8729 | 9443) {
                    crate::tls::inspect(ip, port).await
                } else {
                    String::new()
                };
                Some(ServiceInfo {
                    port: u64::from(port),
                    protocol: "tcp".to_owned(),
                    service: name.to_owned(),
                    banner,
                    tls_cert_info,
                })
            });
        }
        while let Some(result) = probes.join_next().await {
            if let Ok(Some(service)) = result {
                results.push(service);
            }
        }
    }
    results
}

async fn read_banner(client: &mut TcpStream, ip: Ipv4Addr, port: u16) -> String {
    let http = matches!(
        port,
        80 | 81 | 3000 | 3128 | 4200 | 5000 | 5601 | 5984 | 5985 | 7000
            | 7547 | 8000..=8010 | 8080..=8083 | 8086 | 8088 | 8530 | 8888 | 9000 | 9200
    );
    if http
        && client
            .write_all(format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n").as_bytes())
            .await
            .is_err()
    {
        return String::new();
    }
    let mut data = Vec::with_capacity(1024);
    let mut buffer = [0; 1024];
    while data.len() < 8192 {
        let Ok(n) = client.read(&mut buffer).await else {
            break;
        };
        data.extend_from_slice(&buffer[..n]);
        if n == 0
            || (http && data.windows(4).any(|bytes| bytes == b"\r\n\r\n"))
            || (!http && data.contains(&b'\n'))
        {
            break;
        }
    }
    parse_banner(&data, http)
}

pub(crate) fn parse_banner(data: &[u8], http: bool) -> String {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines().map(str::trim);
    let status = lines.next().unwrap_or_default();
    if !http {
        return status.to_owned();
    }
    let mut auth = None;
    for line in lines.take(11).take_while(|line| !line.is_empty()) {
        if let Some((field, value)) = line.split_once(':') {
            if field.eq_ignore_ascii_case("server") && !value.trim().is_empty() {
                return value.trim().to_owned();
            }
            if field.eq_ignore_ascii_case("www-authenticate") && auth.is_none() {
                auth = Some(line);
            }
        }
    }
    auth.unwrap_or(status).to_owned()
}

async fn udp_services(ip: Ipv4Addr) -> Vec<ServiceInfo> {
    let mut probes = JoinSet::new();
    for &(port, name) in UDP_PORTS {
        probes.spawn(async move {
            let (response, banner) = match port {
                161 | 162 => {
                    let reply = udp_exchange(ip, port, SNMP_QUERY, 1000).await;
                    let banner = reply.as_deref().and_then(parse_snmp).unwrap_or_default();
                    (reply.is_some(), banner.to_owned())
                }
                1900 => {
                    let reply = udp_exchange(ip, port, SSDP_QUERY, 1000).await;
                    let banner = reply.as_deref().and_then(parse_ssdp).unwrap_or_default();
                    (reply.is_some(), banner)
                }
                53 => (
                    udp_exchange(ip, port, DNS_QUERY, 200).await.is_some(),
                    String::new(),
                ),
                _ => (
                    udp_exchange(ip, port, &[0], 200).await.is_some(),
                    String::new(),
                ),
            };
            if !response {
                return None;
            }
            Some(ServiceInfo {
                port: u64::from(port),
                protocol: "udp".to_owned(),
                service: name.to_owned(),
                banner,
                ..ServiceInfo::default()
            })
        });
    }
    let mut results = Vec::new();
    while let Some(result) = probes.join_next().await {
        if let Ok(Some(service)) = result {
            results.push(service);
        }
    }
    results
}

const DNS_QUERY: &[u8] = &[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
const SSDP_QUERY: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
const SNMP_QUERY: &[u8] = &[
    0x30, 38, 2, 1, 1, 4, 6, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 25, 2, 1, 1, 2, 1, 0, 2, 1,
    0, 0x30, 14, 0x30, 12, 6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0, 5, 0,
];

async fn udp_exchange(ip: Ipv4Addr, port: u16, request: &[u8], millis: u64) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    socket.connect((ip, port)).await.ok()?;
    socket.send(request).await.ok()?;
    let mut buffer = vec![0; 2048];
    let bytes = timeout(Duration::from_millis(millis), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    buffer.truncate(bytes);
    (!buffer.is_empty()).then_some(buffer)
}

pub(crate) fn parse_ssdp(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let mut discovered = false;
    for line in text.lines() {
        if line.starts_with("HTTP/1.1 200") {
            discovered = true;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("server") && !value.trim().is_empty() {
                return Some(format!("UPnP: {}", value.trim()));
            }
            discovered |= key.eq_ignore_ascii_case("location");
        }
    }
    discovered.then(|| "UPnP Device".to_owned())
}

pub(crate) fn parse_snmp(data: &[u8]) -> Option<&'static str> {
    let (0x30, message, []) = ber(data)? else {
        return None;
    };
    let (2, [1], remaining) = ber(message)? else {
        return None;
    };
    let (4, b"public", remaining) = ber(remaining)? else {
        return None;
    };
    let (0xa2, response, []) = ber(remaining)? else {
        return None;
    };
    let (2, [1], remaining) = ber(response)? else {
        return None;
    };
    let (2, [0], _remaining) = ber(remaining)? else {
        return None;
    };
    Some("SNMP (community=public)")
}

fn ber(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let [tag, size, payload @ ..] = data else {
        return None;
    };
    let (size, payload) = match size {
        0..=127 => (usize::from(*size), payload),
        0x81 => {
            let (length, rest) = payload.split_first()?;
            (usize::from(*length), rest)
        }
        0x82 => {
            let (length, rest) = payload.split_first_chunk::<2>()?;
            (usize::from(u16::from_be_bytes(*length)), rest)
        }
        _ => return None,
    };
    let (value, rest) = payload.split_at_checked(size)?;
    Some((*tag, value, rest))
}

#[cfg(test)]
mod tests {
    use super::{SNMP_QUERY, parse_banner, parse_snmp, parse_ssdp};

    #[test]
    fn prefers_server_header_over_authentication_and_status() {
        assert_eq!(
            parse_banner(
                b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nSeRVeR: example\r\n\r\n",
                true
            ),
            "example",
            "A named server takes precedence"
        );
        assert_eq!(
            parse_banner(b"SSH-2.0-OpenSSH\r\n", false),
            "SSH-2.0-OpenSSH",
            "Keep the SSH banner"
        );
    }

    #[test]
    fn identifies_ssdp_server() {
        assert_eq!(
            parse_ssdp(b"HTTP/1.1 200 OK\r\nServer: Test/1\r\n\r\n").as_deref(),
            Some("UPnP: Test/1"),
            "Extract the advertised server"
        );
        assert!(
            parse_ssdp(b"unrelated").is_none(),
            "Reject unrelated datagrams"
        );
    }

    #[test]
    fn verifies_snmp_response() {
        let mut reply = SNMP_QUERY.to_vec();
        reply[13] = 0xa2;
        assert_eq!(
            parse_snmp(&reply),
            Some("SNMP (community=public)"),
            "Match the response ID and community"
        );
        reply[17] = 2;
        assert!(
            parse_snmp(&reply).is_none(),
            "Reject an unmatched response ID"
        );
    }
}
