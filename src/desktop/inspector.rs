use std::net::Ipv4Addr;

use gpui::{ClipboardItem, Context, Div, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, IconName, Sizable, StyledExt,
    button::{Button, ButtonVariants},
};
use pistonscan::snapshot::{HostResult, ServiceInfo};

use super::state::name;
use crate::Desktop;

pub(crate) fn details(host: &HostResult, expanded: bool, cx: &Context<Desktop>) -> Div {
    let names = [
        ("DNS", &host.hostnames),
        ("mDNS", &host.mdns_names),
        ("NetBIOS", &host.netbios_names),
        ("LLMNR", &host.llmnr_names),
    ]
    .into_iter()
    .flat_map(|(label, values)| {
        values
            .iter()
            .enumerate()
            .filter(|(_, value)| known(value))
            .map(move |(index, value)| field(label, value, Some(index), cx))
    });

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .bg(cx.theme().muted)
        .child(header(host, cx))
        .child(card(
            "Addresses and names",
            std::iter::once(field("IP address", &host.ip, Some(0), cx))
                .chain(
                    known(&host.mac_address)
                        .then(|| field("MAC address", &host.mac_address, Some(0), cx)),
                )
                .chain(names),
        ))
        .when_some(network_identity(host, cx), |panel, identity| {
            panel.child(identity)
        })
        .when_some(host.air_play.as_ref(), |view, airplay| {
            view.child(card(
                "AirPlay metadata",
                std::iter::once(field(
                    "Endpoint",
                    &format!("/{}", airplay.endpoint),
                    None,
                    cx,
                ))
                .chain(
                    airplay
                        .fields
                        .iter()
                        .map(|(label, value)| field(label, value, None, cx)),
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
        .when(
            !host.latency_samples.is_empty() || host.latency_ms > 0.,
            |panel| panel.child(latency(host, cx)),
        )
        .when(!host.discovery_sources.is_empty(), |panel| {
            panel.child(card(
                "Discovery sources",
                [field(
                    "Sources",
                    &host.discovery_sources.join(", "),
                    None,
                    cx,
                )],
            ))
        })
        .child(raw_record(host.clone(), expanded, cx))
}

fn latency(host: &HostResult, cx: &Context<Desktop>) -> Div {
    card(
        "Latency",
        std::iter::once(field(
            "Average",
            &format!("{:.2} ms", host.latency_ms),
            None,
            cx,
        ))
        .chain((!host.latency_samples.is_empty()).then(|| {
            field(
                "Samples",
                &host
                    .latency_samples
                    .iter()
                    .map(|sample| format!("{sample:.2} ms"))
                    .collect::<Vec<_>>()
                    .join(", "),
                None,
                cx,
            )
        })),
    )
}

fn header(host: &HostResult, cx: &Context<Desktop>) -> Div {
    let icon = super::results::device_icon(host);
    let theme = cx.theme();
    let title = name(host).to_owned();
    let subtitle = super::results::device_subtitle(host);
    div()
        .flex()
        .justify_between()
        .items_start()
        .gap_2()
        .child(gpui_component::Icon::new(icon).size_6().flex_shrink_0())
        .child(
            div()
                .flex_1()
                .min_w_0()
                .child(
                    div()
                        .text_lg()
                        .font_bold()
                        .id("inspector-name")
                        .line_clamp(2)
                        .child(title.clone())
                        .tooltip(move |window, cx| {
                            gpui_component::tooltip::Tooltip::new(title.clone()).build(window, cx)
                        }),
                )
                .when(!subtitle.is_empty(), |header| {
                    header.child(
                        div()
                            .text_sm()
                            .truncate()
                            .text_color(theme.muted_foreground)
                            .child(subtitle),
                    )
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_xs()
                        .child(div().size(px(6.)).rounded_full().bg(if host.reachable {
                            theme.success
                        } else {
                            theme.muted_foreground
                        }))
                        .child(if host.reachable { "Online" } else { "Offline" }),
                ),
        )
        .child(
            Button::new("close-inspector")
                .small()
                .ghost()
                .icon(IconName::Close)
                .tooltip("Close inspector (Esc)")
                .on_click(cx.listener(|view, _, window, cx| {
                    view.inspector = false;
                    window.focus(&view.focus);
                    cx.notify();
                })),
        )
}

fn network_identity(host: &HostResult, cx: &Context<Desktop>) -> Option<Div> {
    let identity = [
        ("Manufacturer", host.manufacturer.clone()),
        ("OS", host.os_guess.clone()),
        ("TTL", known_count(host.ttl)),
        ("Checks", known_count(host.attempts)),
    ];
    let fields = identity
        .iter()
        .map(|(label, value)| (*label, value.as_str()))
        .chain(host.smb_info.iter().flat_map(|smb| {
            [
                ("SMB name", smb.computer_name.as_str()),
                ("SMB domain", smb.domain.as_str()),
                ("SMB source", smb.source.as_str()),
            ]
        }))
        .filter(|(_, value)| known(value))
        .map(|(label, value)| field(label, value, None, cx))
        .collect::<Vec<_>>();
    (!fields.is_empty()).then(|| card("Network identity", fields))
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

fn known(value: &str) -> bool {
    !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("unknown")
}

fn known_count(value: u64) -> String {
    if value == 0 {
        String::new()
    } else {
        value.to_string()
    }
}

fn field(label: &str, value: &str, copy_index: Option<usize>, cx: &Context<Desktop>) -> Div {
    let copy = value.to_owned();
    div()
        .flex()
        .items_start()
        .gap_2()
        .text_sm()
        .child(
            div()
                .w(px(96.))
                .flex_shrink_0()
                .text_color(cx.theme().muted_foreground)
                .child(label.to_owned()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .child(value.to_owned()),
        )
        .when_some(copy_index, |row, index| {
            row.child(
                Button::new((gpui::SharedString::from(label.to_owned()), index))
                    .small()
                    .ghost()
                    .icon(IconName::Copy)
                    .tooltip(format!("Copy {label}"))
                    .on_click(move |_, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                    }),
            )
        })
}

fn card(title: &'static str, entries: impl IntoIterator<Item = Div>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().font_bold().child(title))
        .children(entries)
}

fn service_detail(host: &HostResult, service: &ServiceInfo, cx: &Context<Desktop>) -> Div {
    let endpoint = format!("({}/{})", service.port, service.protocol.to_uppercase());
    let label = format!("{} {endpoint}", service.service);
    let mut row = div()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .rounded_md()
        .border_1()
        .border_color(cx.theme().border)
        .bg(cx.theme().background)
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_baseline()
                .gap_x_2()
                .text_sm()
                .font_bold()
                .child(service.service.clone())
                .child(div().whitespace_nowrap().child(endpoint)),
        );
    if let Some((action, url)) = service_url(host, service) {
        let copy = url.clone();
        row = row.child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(
                    Button::new(gpui::SharedString::from(format!("{label}-open")))
                        .small()
                        .outline()
                        .label(action)
                        .on_click(move |_, _, cx| cx.open_url(&url)),
                )
                .when(action == "Open in browser", |actions| {
                    actions.child(
                        Button::new(gpui::SharedString::from(format!("{label}-copy")))
                            .small()
                            .outline()
                            .label("Copy URL")
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                            }),
                    )
                }),
        );
    }
    if service.port == 22
        && service.protocol.eq_ignore_ascii_case("tcp")
        && let Ok(ip) = host.ip.parse::<Ipv4Addr>()
    {
        row = row.child(
            Button::new("ssh-command")
                .small()
                .outline()
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
    let warning =
        expiry.and_then(|expiry| certificate_warning(expiry, chrono::Utc::now().date_naive()));
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
        .children(
            summary
                .split("; ")
                .map(|field| match field.split_once('=') {
                    Some(("CN", value)) => self::field("Subject", value, None, cx),
                    Some(("SANs", value)) => self::field("DNS names", value, None, cx),
                    Some(("Issuer", value)) => self::field("Issuer", value, None, cx),
                    Some(("Expires", value)) => self::field("Expires", value, None, cx),
                    _ => div().overflow_hidden().child(field.to_owned()),
                }),
        )
}

fn certificate_warning(
    expiry: chrono::NaiveDate,
    today: chrono::NaiveDate,
) -> Option<&'static str> {
    match (expiry - today).num_days() {
        ..=-1 => Some("Certificate expired"),
        0..=30 => Some("Certificate expires soon"),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::{certificate_warning, known, known_count};

    #[test]
    fn unknown_values_are_hidden() {
        assert!(
            !known("  Unknown  "),
            "Omit placeholder text from older snapshots"
        );
        assert!(!known(""), "Omit missing text");
        assert!(known("Linux"), "Keep known identity values");
        assert_eq!(known_count(0), "", "Omit the default TTL");
        assert_eq!(known_count(64), "64", "Keep a measured TTL");
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report incorrect expiry messages"
    )]
    fn certificate_warnings_use_the_expiry_date() -> Result<(), chrono::ParseError> {
        let date = |value| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d");
        let today = date("2026-11-19")?;
        assert_eq!(
            certificate_warning(date("2026-11-18")?, today),
            Some("Certificate expired"),
            "Warn about expired certificates"
        );
        assert_eq!(
            certificate_warning(date("2026-12-19")?, today),
            Some("Certificate expires soon"),
            "Warn up to 30 days before expiry"
        );
        assert_eq!(
            certificate_warning(date("2026-12-20")?, today),
            None,
            "Omit warnings outside the 30-day window"
        );
        Ok(())
    }
}
