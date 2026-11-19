use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::{net::TcpStream, time::timeout};
use x509_parser::extensions::GeneralName;

pub async fn inspect(ip: Ipv4Addr, port: u16) -> String {
    timeout(Duration::from_millis(500), handshake(ip, port))
        .await
        .unwrap_or_default()
        .unwrap_or_default()
}

async fn handshake(ip: Ipv4Addr, port: u16) -> Option<String> {
    // Discovery reads certificate metadata even for private or expired certificates.
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let client = TcpStream::connect((ip, port)).await.ok()?;
    let stream = tokio_native_tls::TlsConnector::from(connector)
        .connect(&ip.to_string(), client)
        .await
        .ok()?;
    let cert = stream.get_ref().peer_certificate().ok()??;
    let der = cert.to_der().ok()?;
    summarize(&der)
}

fn summarize(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let subject = cert
        .subject()
        .iter_common_name()
        .find_map(|attr| attr.as_str().ok());
    let issuer = cert
        .issuer()
        .iter_common_name()
        .find_map(|attr| attr.as_str().ok());
    let mut fields = Vec::new();
    if let Some(subject) = subject {
        fields.push(format!("CN={subject}"));
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let names = san
            .value
            .general_names
            .iter()
            .filter_map(|name| {
                if let GeneralName::DNSName(name) = name {
                    Some(*name)
                } else {
                    None
                }
            })
            .take(3)
            .collect::<Vec<&str>>();
        if !names.is_empty() {
            fields.push(format!("SANs={}", names.join(",")));
        }
    }
    let date = cert.validity().not_after.to_datetime().date();
    fields.push(format!("Expires={date}"));
    if let Some(issuer) = issuer.filter(|value| Some(*value) != subject) {
        fields.push(format!("Issuer={issuer}"));
    }
    Some(fields.join("; "))
}

#[cfg(test)]
mod tests {
    use super::summarize;

    #[test]
    fn extracts_subject_san_and_expiry() {
        let summary = summarize(include_bytes!("../tests/fixtures/synthetic-server.der"));
        assert!(summary.as_ref().is_some_and(|summary| {
            summary.starts_with("CN=scanner-fixture.test; SANs=scanner-fixture.test,other-fixture.test; Expires=")
                && !summary.contains("Issuer=")
        }), "Report the certificate fields and omit its identical issuer");
    }

    #[test]
    fn rejects_truncated_certificate() {
        assert!(
            summarize(&[0x30, 0x82, 0]).is_none(),
            "Reject truncated DER"
        );
    }
}
