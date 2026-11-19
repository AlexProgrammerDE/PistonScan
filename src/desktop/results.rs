use std::cmp::Ordering;
use std::net::Ipv4Addr;

use gpui::{ClipboardItem, Context, Div, IntoElement, Stateful, div, prelude::*};
use gpui_component::{
    ActiveTheme, Disableable, Sizable, StyledExt, button::Button, checkbox::Checkbox,
};
use pistonscan::snapshot::{HostResult, ServiceInfo};

use crate::Desktop;

#[derive(Clone, Copy, Default)]
pub enum Sort {
    #[default]
    Insights,
    Latency,
    Address,
}

impl Sort {
    fn compare(self, a: &HostResult, b: &HostResult) -> Ordering {
        let latency = || match (a.reachable, b.reachable) {
            (true, true) => a.latency_ms.total_cmp(&b.latency_ms),
            (false, false) => Ordering::Equal,
            _ => b.reachable.cmp(&a.reachable),
        };
        let address = || match (a.ip.parse::<Ipv4Addr>(), b.ip.parse::<Ipv4Addr>()) {
            (Ok(first), Ok(second)) => first.cmp(&second),
            _ => a.ip.cmp(&b.ip),
        };
        match self {
            Self::Insights => b.insight_score.cmp(&a.insight_score),
            Self::Latency => latency(),
            Self::Address => address(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Insights => "Highest insights",
            Self::Latency => "Lowest latency",
            Self::Address => "IP address",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Insights => Self::Latency,
            Self::Latency => Self::Address,
            Self::Address => Self::Insights,
        }
    }
}

const COLUMNS: [(&str, f32); 11] = [
    ("", 64.),
    ("Device", 152.),
    ("IP Address", 120.),
    ("MAC", 140.),
    ("Manufacturer", 142.),
    ("OS", 112.),
    ("Latency (ms)", 90.),
    ("Services", 120.),
    ("Insights", 72.),
    ("Status", 90.),
    ("Notes", 192.),
];

impl Desktop {
    pub fn results(&self, cx: &Context<Self>) -> impl IntoElement {
        let maximum = self
            .snapshot
            .results
            .iter()
            .map(|host| host.insight_score)
            .max()
            .unwrap_or_default();
        let minimum = self.minimum.min(maximum);
        let mut visible = self
            .snapshot
            .results
            .iter()
            .filter(|host| {
                (!self.reachable_only || host.reachable)
                    && (!self.successful_only || (host.reachable && host.error.is_empty()))
                    && host.insight_score >= minimum
            })
            .collect::<Vec<_>>();
        visible.sort_by(|a, b| self.sort.compare(a, b));
        let count = format!("{} / {} hosts", visible.len(), self.snapshot.results.len());
        let empty = if self.snapshot.results.is_empty() {
            "No scan data yet. Start a scan to populate results."
        } else {
            "No results match the current filters."
        };
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .gap_2()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(div().text_lg().child("Scan Results"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(count),
                    ),
            )
            .child(self.filters(minimum, maximum, cx))
            .child(
                div()
                    .id("results")
                    .flex_1()
                    .overflow_scroll()
                    .border_1()
                    .rounded_md()
                    .border_color(cx.theme().border)
                    .child(
                        div()
                            .min_w(gpui::px(COLUMNS.iter().map(|(_, width)| width + 8.).sum()))
                            .child(
                                table_row(cx).bg(cx.theme().muted).children(
                                    COLUMNS.iter().enumerate().map(|(index, (label, _))| {
                                        cell(index, (*label).to_owned())
                                    }),
                                ),
                            )
                            .when(visible.is_empty(), |table| {
                                table.child(
                                    div()
                                        .p_4()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(empty),
                                )
                            })
                            .children(visible.into_iter().map(|host| self.host_row(host, cx))),
                    ),
            )
    }

    fn filters(&self, minimum: u64, maximum: u64, cx: &Context<Self>) -> Div {
        div()
            .flex()
            .items_center()
            .gap_3()
            .child(
                Checkbox::new("reachable")
                    .checked(self.reachable_only)
                    .label("Reachable only")
                    .on_click(cx.listener(|view, value, _, cx| {
                        view.reachable_only = *value;
                        cx.notify();
                    })),
            )
            .child(
                Checkbox::new("successful")
                    .checked(self.successful_only)
                    .label("Successful only")
                    .on_click(cx.listener(|view, value, _, cx| {
                        view.successful_only = *value;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("lower-insights")
                    .small()
                    .label("-")
                    .disabled(minimum == 0)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.minimum = minimum.saturating_sub(1);
                        cx.notify();
                    })),
            )
            .child(format!("Minimum insights {minimum}"))
            .child(
                Button::new("raise-insights")
                    .small()
                    .label("+")
                    .disabled(minimum >= maximum)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.minimum = minimum.saturating_add(1);
                        cx.notify();
                    })),
            )
            .children([("All data", 0), ("Enriched", 5), ("Deep scan", 10)].map(
                |(label, value)| {
                    Button::new(label)
                        .small()
                        .label(label)
                        .disabled(maximum == 0)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.minimum = value.min(maximum);
                            cx.notify();
                        }))
                },
            ))
            .child(
                Button::new("sort")
                    .small()
                    .label(format!("Sort · {}", self.sort.label()))
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.sort = view.sort.next();
                        cx.notify();
                    })),
            )
    }

    fn host_row(&self, host: &HostResult, cx: &Context<Self>) -> Stateful<Div> {
        let expanded = self.expanded.contains(&host.ip);
        let ip = host.ip.clone();
        let preview = host
            .services
            .iter()
            .take(3)
            .map(|svc| svc.service.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let status = if host.reachable {
            "Reachable"
        } else {
            "No response"
        };
        let notes = if host.error.is_empty() {
            observations(host).join(", ")
        } else {
            host.error.clone()
        };
        div()
            .id(gpui::SharedString::from(host.ip.clone()))
            .child(
                table_row(cx)
                    .child(
                        div().w(gpui::px(COLUMNS[0].1)).child(
                            Button::new("expand")
                                .small()
                                .label(if expanded { "Hide" } else { "View" })
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    if !view.expanded.remove(&ip) {
                                        view.expanded.insert(ip.clone());
                                    }
                                    cx.notify();
                                })),
                        ),
                    )
                    .child(cell(1, host.device_name.clone()))
                    .child(cell(2, host.ip.clone()))
                    .child(cell(3, host.mac_address.clone()))
                    .child(cell(4, host.manufacturer.clone()))
                    .child(cell(5, host.os_guess.clone()))
                    .child(cell(
                        6,
                        if host.reachable {
                            format!("{:.2}", host.latency_ms)
                        } else {
                            String::new()
                        },
                    ))
                    .child(cell(7, preview))
                    .child(cell(8, host.insight_score.to_string()))
                    .child(cell(9, status.to_owned()))
                    .child(cell(10, notes)),
            )
            .when(expanded, |row| row.child(details(host, cx)))
    }
}

fn table_row(cx: &Context<Desktop>) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .px_2()
        .py_2()
        .border_b_1()
        .border_color(cx.theme().border)
}

fn cell(index: usize, text: String) -> Div {
    div()
        .w(gpui::px(COLUMNS[index].1))
        .flex_shrink_0()
        .truncate()
        .child(if text.is_empty() {
            "–".to_owned()
        } else {
            text
        })
}

fn details(host: &HostResult, cx: &Context<Desktop>) -> Div {
    let raw = serde_json::to_string_pretty(host).unwrap_or_default();
    let copy = raw.clone();
    let mut identity = vec![
        format!("IP {}", host.ip),
        format!("MAC {}", host.mac_address),
        format!("Manufacturer {}", host.manufacturer),
        format!("Device {}", host.device_name),
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
    .map(|(label, values)| format!("{label}  {}", values.join(", ")));

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_3()
        .bg(cx.theme().muted)
        .child(
            div()
                .flex()
                .gap_5()
                .child(card("Network identity", identity))
                .child(card("Latency", latency))
                .child(card("Discovery sources", host.discovery_sources.clone())),
        )
        .child(card("Hostnames", names))
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
                .child(format!("Services ({})", host.services.len()))
                .children(
                    host.services
                        .iter()
                        .map(|service| service_detail(host, service)),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child("Raw record")
                .child(
                    Button::new("copy-json")
                        .small()
                        .label("Copy JSON")
                        .on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                        }),
                ),
        )
        .child(div().text_xs().child(raw))
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

fn service_detail(host: &HostResult, service: &ServiceInfo) -> Div {
    let label = format!(
        "{} ({}/{})",
        service.service,
        service.port,
        service.protocol.to_uppercase()
    );
    let mut row = div().flex().flex_col().items_start();
    if let Some(url) = service_url(host, service) {
        row = row.child(
            Button::new(gpui::SharedString::from(label.clone()))
                .small()
                .label(label)
                .on_click(move |_, _, cx| cx.open_url(&url)),
        );
    } else {
        row = row.child(label);
    }
    for detail in [&service.banner, &service.tls_cert_info] {
        if !detail.is_empty() {
            row = row.child(div().text_sm().child(detail.clone()));
        }
    }
    row
}

fn service_url(host: &HostResult, service: &ServiceInfo) -> Option<String> {
    if !service.protocol.eq_ignore_ascii_case("tcp") {
        return None;
    }
    let name = service.service.to_ascii_lowercase();
    let https =
        !service.tls_cert_info.is_empty() || https_port(service.port) || name.contains("https");
    if !https && !http_port(service.port) && !name.contains("http") && !name.contains("web") {
        return None;
    }
    let ip = host.ip.parse::<Ipv4Addr>().ok()?;
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
    Some(format!("{scheme}://{endpoint}{suffix}"))
}

fn observations(host: &HostResult) -> Vec<String> {
    let mut notes = Vec::new();
    if host.reachable && host.latency_ms > 0. && host.latency_ms <= 5. {
        notes.push("Very low latency".to_owned());
    } else if host.latency_ms > 120. {
        notes.push(format!("High latency ({:.2} ms)", host.latency_ms));
    }
    if let Some(name) = host.hostnames.first().or_else(|| host.mdns_names.first()) {
        notes.push(format!("Hostname: {name}"));
    }
    if let Some(info) = &host.smb_info {
        if !info.computer_name.is_empty() {
            notes.push(format!("SMB workstation: {}", info.computer_name));
        }
        if !info.domain.is_empty() {
            notes.push(format!("SMB domain: {}", info.domain));
        }
    }
    notes.extend(
        host.discovery_sources
            .iter()
            .take(2)
            .map(|source| format!("Seen via {source}")),
    );
    for service in &host.services {
        add_service_observations(&mut notes, service);
    }
    if let Some(info) = &host.air_play
        && !info.fields.is_empty()
    {
        let model = ["model", "hwmodel", "deviceid", "name"]
            .into_iter()
            .find_map(|key| {
                info.fields
                    .iter()
                    .find_map(|(field, value)| field.eq_ignore_ascii_case(key).then_some(value))
            });
        notes.push(model.map_or_else(
            || "AirPlay service metadata".to_owned(),
            |model| format!("AirPlay: {model}"),
        ));
    }
    if !host.os_guess.is_empty() && host.os_guess != "Unknown" {
        notes.push(format!("OS likely {}", host.os_guess));
    }
    notes.truncate(5);
    notes
}

fn add_service_observations(notes: &mut Vec<String>, service: &ServiceInfo) {
    let name = service.service.to_ascii_lowercase();
    let port = service.port;
    let mut add = |message: &str| {
        if !notes.iter().any(|note| note == message) {
            notes.push(message.to_owned());
        }
    };
    for (ports, names, message) in [
        (&[3389][..], &["rdp"][..], "RDP exposed"),
        (&[445], &["smb"], "SMB file sharing"),
        (&[22], &["ssh"], "SSH remote access"),
        (&[21], &["ftp"], "FTP (unencrypted)"),
        (&[23], &["telnet"], "Telnet (unencrypted)"),
        (&[25], &["smtp"], "SMTP service"),
    ] {
        if ports.contains(&port) || names.iter().any(|key| name.contains(key)) {
            add(message);
        }
    }
    if https_port(port) || name.contains("https") || !service.tls_cert_info.is_empty() {
        add(&format!("HTTPS on {port}"));
    } else if http_port(port) || name.contains("http") {
        add(&format!("HTTP on {port}"));
    }
    for (ports, names, message) in [
        (&[161][..], &["snmp"][..], "SNMP management interface"),
        (&[5985, 5986], &["winrm"], "WinRM remote management"),
        (&[7547], &["tr-069"], "TR-069 remote management"),
        (&[8291], &["winbox"], "MikroTik WinBox service"),
        (&[8728, 8729], &["mikrotik"], "MikroTik API endpoint"),
        (&[515], &["lpd"], "LPD printing available"),
        (
            &[9100],
            &["jetdirect", "printer"],
            "Printer raw port (JetDirect)",
        ),
        (&[3306], &["mysql"], "MySQL database service"),
        (&[5432], &["postgres"], "PostgreSQL database service"),
        (&[1433], &["mssql"], "Microsoft SQL Server"),
        (&[6379], &["redis"], "Redis data store"),
        (&[27_017], &["mongo"], "MongoDB database"),
        (&[9200], &["elastic"], "Elasticsearch endpoint"),
    ] {
        if ports.contains(&port) || names.iter().any(|key| name.contains(key)) {
            add(message);
        }
    }
    let banner = service.banner.to_ascii_lowercase();
    if banner.contains("openssh") {
        add("OpenSSH banner");
    } else if banner.contains("microsoft") {
        add("Microsoft service banner");
    }
}

fn http_port(port: u64) -> bool {
    matches!(port, 80 | 81 | 3000 | 3128 | 4200 | 5000 | 5601 | 5984 | 5985 | 7000 |
        7547 | 8000..=8010 | 8080..=8083 | 8086 | 8088 | 8530 | 8888 | 9000 | 9200)
}

fn https_port(port: u64) -> bool {
    matches!(port, 443 | 4443 | 5986 | 8443 | 8729 | 9443)
}
