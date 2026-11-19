use std::{
    net::{Ipv4Addr, UdpSocket},
    path::PathBuf,
};

use gpui::{Context, IntoElement, div, prelude::*};
use gpui_component::{ActiveTheme, StyledExt, checkbox::Checkbox, input::Input};
use serde::{Deserialize, Serialize};

use super::state::{Filter, Sort};
use crate::Desktop;

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct Preferences {
    pub target: String,
    pub threads: String,
    pub delay: String,
    pub filter: Filter,
    pub sort: Sort,
    pub window_size: Option<(f32, f32)>,
    pub probes: pistonscan::ping::ProbeGroups,
    pub columns: [f32; 3],
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            target: String::new(),
            threads: String::new(),
            delay: String::new(),
            filter: Filter::default(),
            sort: Sort::default(),
            window_size: None,
            probes: pistonscan::ping::ProbeGroups::default(),
            columns: [104., 88., 116.],
        }
    }
}

impl Preferences {
    fn path() -> Option<PathBuf> {
        let base = if cfg!(target_os = "windows") {
            std::env::var_os("APPDATA").map(PathBuf::from)
        } else {
            let home = || std::env::var_os("HOME").map(PathBuf::from);
            if cfg!(target_os = "macos") {
                home().map(|path| path.join("Library/Application Support"))
            } else {
                std::env::var_os("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .or_else(|| home().map(|path| path.join(".config")))
            }
        };
        Some(base?.join("pistonscan/preferences.json"))
    }

    pub(crate) fn load(runtime: &tokio::runtime::Runtime) -> Self {
        Self::path()
            .and_then(|path| runtime.block_on(tokio::fs::read(path)).ok())
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }
}

pub(crate) fn local_target() -> Option<(String, String)> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    let primary = socket
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .ok()
        .and_then(|()| socket.local_addr().ok())
        .map(|address| address.ip());
    let interfaces = if_addrs::get_if_addrs().ok()?;
    let (interface, address) = interfaces
        .iter()
        .filter(|interface| interface.is_oper_up() && !interface.is_loopback())
        .filter_map(|interface| match &interface.addr {
            if_addrs::IfAddr::V4(address) => Some((interface, address)),
            if_addrs::IfAddr::V6(_) => None,
        })
        .min_by_key(|(_, address)| primary != Some(address.ip.into()))?;
    let prefix = address.prefixlen;
    let mask = u32::MAX
        .checked_shl(32u32.saturating_sub(u32::from(prefix)))
        .unwrap_or_default();
    let network = Ipv4Addr::from(u32::from(address.ip) & mask);
    Some((
        format!("{} · {}/{prefix}", interface.name, address.ip),
        format!("{network}/{prefix}"),
    ))
}

impl Desktop {
    pub(crate) fn save(&self, cx: &Context<Self>) {
        let Some(path) = Preferences::path() else {
            return;
        };
        let Some(parent) = path.parent() else { return };
        let preferences = Preferences {
            target: self.target.read(cx).value().to_string(),
            threads: self.threads.read(cx).value().to_string(),
            delay: self.delay.read(cx).value().to_string(),
            filter: self.filter,
            sort: self.sort,
            window_size: self.window_size,
            probes: self.probes,
            columns: self.columns,
        };
        let Ok(data) = serde_json::to_vec_pretty(&preferences) else {
            return;
        };
        let parent = parent.to_owned();
        if let Err(error) = self.runtime.block_on(async {
            tokio::fs::create_dir_all(parent).await?;
            let pending = path.with_extension("tmp");
            tokio::fs::write(&pending, data).await?;
            tokio::fs::rename(pending, path).await
        }) {
            eprintln!("Cannot save PistonScan preferences: {error}");
        }
    }

    pub(crate) fn settings(&self, cx: &Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        div()
            .px_5()
            .py_4()
            .bg(theme.muted)
            .border_b_1()
            .border_color(theme.border)
            .child(div().font_bold().mb_3().child("Scan settings"))
            .child(
                div()
                    .flex()
                    .gap_5()
                    .child(
                        div()
                            .flex_1()
                            .child("Concurrent checks")
                            .child(Input::new(&self.threads))
                            .child(
                                div()
                                    .mt_1()
                                    .text_sm()
                                    .text_color(theme.muted_foreground)
                                    .child("Lower this if scanning slows down your network."),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .child("Delay between checks (ms)")
                            .child(Input::new(&self.delay))
                            .child(
                                div()
                                    .mt_1()
                                    .text_sm()
                                    .text_color(theme.muted_foreground)
                                    .child("Increase this to send probes less often."),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_4()
                    .mt_3()
                    .child(
                        Checkbox::new("probe-names")
                            .label("Look up device names")
                            .checked(self.probes.names)
                            .on_click(cx.listener(|view, value, _, cx| {
                                view.probes.names = *value;
                                view.save(cx);
                                cx.notify();
                            })),
                    )
                    .child(
                        Checkbox::new("probe-services")
                            .label("Check for open services")
                            .checked(self.probes.services)
                            .on_click(cx.listener(|view, value, _, cx| {
                                view.probes.services = *value;
                                view.save(cx);
                                cx.notify();
                            })),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::Preferences;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions describe preference compatibility failures"
    )]
    fn preferences_preserve_values_and_accept_older_files() -> Result<(), serde_json::Error> {
        let prefs: Preferences = serde_json::from_str(
            r#"{"target":"192.0.2.0/24","window_size":[1100,740],"filter":"Services"}"#,
        )?;
        let saved = serde_json::to_value(prefs)?;
        assert_eq!(saved["target"], "192.0.2.0/24", "Remember the scan target");
        assert_eq!(
            saved["window_size"],
            serde_json::json!([1100.0, 740.0]),
            "Remember the window size"
        );
        assert_eq!(saved["filter"], "Services", "Remember the device filter");
        assert_eq!(saved["delay"], "", "Allow older settings without a delay");
        Ok(())
    }
}
