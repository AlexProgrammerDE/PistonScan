use std::net::Ipv4Addr;

use gpui::{ClipboardItem, Context, Div, div, prelude::*};
use gpui_component::{ActiveTheme, Sizable, StyledExt, button::Button};
use pistonscan::snapshot::{HostResult, ServiceInfo};

use super::state::name;
use crate::Desktop;

pub(crate) fn details(host: &HostResult, expanded: bool, cx: &Context<Desktop>) -> Div {
    let host_record = host.clone();
    let mut identity = vec![
        format!("Manufacturer {}", host.manufacturer),
        format!("OS {}", host.os_guess),
        format!("TTL {}", host.ttl),
        format!("Checks {}", host.attempts),
    ];
    if let Some(smb) = &host.smb_info {
        identity.extend([
            format!("SMB name {}", smb.computer_name),
            format!("SMB domain {}", smb.domain),
            format!("SMB source {}", smb.source),
        ]);
    }
    let mut latency = vec![format!("Average {:.2} ms", host.latency_ms)];
    latency.extend(
        host.latency_samples
            .iter()
            .map(|sample| format!("{sample:.2} ms")),
    );
    let names = [
        ("DNS", &host.hostnames),
        ("mDNS", &host.mdns_names),
        ("NetBIOS", &host.netbios_names),
        ("LLMNR", &host.llmnr_names),
    ]
    .into_iter()
    .flat_map(|(label, values)| values.iter().map(move |value| copy_field(label, value)));

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .bg(cx.theme().muted)
        .child(
            div()
                .flex()
                .justify_between()
                .items_start()
                .gap_2()
                .child(div().text_lg().font_bold().child(name(host).to_owned()))
                .child(
                    Button::new("close-inspector")
                        .small()
                        .label("Close")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.inspector = false;
                            cx.notify();
                        })),
                ),
        )
        .child(copy_field("IP address", &host.ip))
        .when(!host.mac_address.is_empty(), |panel| {
            panel.child(copy_field("MAC address", &host.mac_address))
        })
        .child(card("Network identity", identity))
        .children(names)
        .when_some(host.air_play.as_ref(), |view, airplay| {
            view.child(card(
                "AirPlay metadata",
                std::iter::once(format!("Endpoint /{}", airplay.endpoint)).chain(
                    airplay
                        .fields
                        .iter()
                        .map(|(field, value)| format!("{field}  {value}")),
                ),
            ))
        })
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .font_bold()
                        .child(format!("Services ({})", host.services.len())),
                )
                .children(
                    host.services
                        .iter()
                        .map(|service| service_detail(host, service, cx)),
                ),
        )
        .child(card("Latency", latency))
        .when(!host.discovery_sources.is_empty(), |panel| {
            panel.child(card("Discovery sources", host.discovery_sources.clone()))
        })
        .child(raw_record(host_record, expanded, cx))
}

fn raw_record(host_record: HostResult, expanded: bool, cx: &Context<Desktop>) -> Div {
    let raw = expanded.then(|| serde_json::to_string_pretty(&host_record).unwrap_or_default());
    div()
        .child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("raw-record")
                        .small()
                        .label(if expanded { "Hide JSON" } else { "View JSON" })
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.raw = !view.raw;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("copy-json")
                        .small()
                        .label("Copy JSON")
                        .on_click(move |_, _, cx| {
                            if let Ok(json) = serde_json::to_string_pretty(&host_record) {
                                cx.write_to_clipboard(ClipboardItem::new_string(json));
                            }
                        }),
                ),
        )
        .when_some(raw, |panel, raw| panel.child(div().text_xs().child(raw)))
}

fn copy_field(label: &'static str, value: &str) -> Div {
    let copy = value.to_owned();
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_2()
        .child(div().text_sm().child(label))
        .child(
            Button::new(label)
                .small()
                .label(value.to_owned())
                .tooltip("Copy to clipboard")
                .on_click(move |_, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                }),
        )
}

fn card(title: &'static str, entries: impl IntoIterator<Item = String>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().font_bold().child(title))
        .children(
            entries
                .into_iter()
                .map(|entry| div().text_sm().child(entry)),
        )
}

fn service_detail(host: &HostResult, service: &ServiceInfo, cx: &Context<Desktop>) -> Div {
    let label = format!(
        "{} ({}/{})",
        service.service,
        service.port,
        service.protocol.to_uppercase()
    );
    let mut row = div().flex().flex_col().items_start();
    if let Some((action, url)) = service_url(host, service) {
        row = row.child(
            Button::new(gpui::SharedString::from(label.clone()))
                .small()
                .label(action)
                .on_click(move |_, _, cx| cx.open_url(&url)),
        );
    }
    row = row.child(div().text_sm().child(label));
    if service.port == 22
        && service.protocol.eq_ignore_ascii_case("tcp")
        && let Ok(ip) = host.ip.parse::<Ipv4Addr>()
    {
        row = row.child(
            Button::new("ssh-command")
                .small()
                .label("Copy SSH command")
                .on_click(move |_, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(format!("ssh {ip}")));
                }),
        );
    }
    if !service.banner.is_empty() {
        row = row.child(div().text_sm().child(service.banner.clone()));
    }
    if !service.tls_cert_info.is_empty() {
        row = row.child(certificate(&service.tls_cert_info, cx));
    }
    row
}

fn certificate(summary: &str, cx: &Context<Desktop>) -> Div {
    let expiry = summary
        .split("; ")
        .find_map(|field| field.strip_prefix("Expires="))
        .and_then(|date| chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok());
    let warning = expiry.and_then(|expiry| {
        let remaining = (expiry - chrono::Utc::now().date_naive()).num_days();
        (remaining <= 30).then_some(if remaining < 0 {
            "Certificate expired"
        } else {
            "Certificate expires soon"
        })
    });
    div()
        .text_xs()
        .text_color(cx.theme().muted_foreground)
        .when_some(warning, |panel, warning| {
            panel.child(
                div()
                    .text_color(cx.theme().danger)
                    .font_bold()
                    .child(warning),
            )
        })
        .children(summary.split("; ").map(|field| {
            let label = match field.split_once('=') {
                Some(("CN", value)) => format!("Subject  {value}"),
                Some(("SANs", value)) => format!("DNS names  {value}"),
                Some(("Issuer", value)) => format!("Issuer  {value}"),
                Some(("Expires", value)) => format!("Expires  {value}"),
                _ => field.to_owned(),
            };
            div().child(label)
        }))
}

fn service_url(host: &HostResult, service: &ServiceInfo) -> Option<(&'static str, String)> {
    if !service.protocol.eq_ignore_ascii_case("tcp") {
        return None;
    }
    let ip = host.ip.parse::<Ipv4Addr>().ok()?;
    if service.port == 445 {
        let url = if cfg!(windows) {
            format!(r"\\{ip}")
        } else {
            format!("smb://{ip}")
        };
        return Some(("Open file sharing", url));
    }
    let name = service.service.to_ascii_lowercase();
    let https =
        !service.tls_cert_info.is_empty() || https_port(service.port) || name.contains("https");
    if !https && !http_port(service.port) && !name.contains("http") && !name.contains("web") {
        return None;
    }
    let endpoint = host
        .hostnames
        .iter()
        .chain(&host.mdns_names)
        .find(|name| {
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
                && !name.is_empty()
        })
        .cloned()
        .unwrap_or_else(|| ip.to_string());
    let scheme = if https { "https" } else { "http" };
    let suffix = if service.port == if https { 443 } else { 80 } {
        String::new()
    } else {
        format!(":{}", service.port)
    };
    Some(("Open in browser", format!("{scheme}://{endpoint}{suffix}")))
}

fn http_port(port: u64) -> bool {
    matches!(port, 80 | 81 | 3000 | 3128 | 4200 | 5000 | 5601 | 5984 | 5985 | 7000 |
        7547 | 8000..=8010 | 8080..=8083 | 8086 | 8088 | 8530 | 8888 | 9000 | 9200)
}

fn https_port(port: u64) -> bool {
    matches!(port, 443 | 4443 | 5986 | 8443 | 8729 | 9443)
}
