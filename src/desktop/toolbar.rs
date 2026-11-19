use gpui::{Context, IntoElement, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, Disableable, IconName, StyledExt,
    button::{Button, ButtonVariants},
    input::Input,
};
use pistonscan::snapshot::ScanStatus;

use super::state::target_count;
use crate::{Desktop, ToolbarPanel};

impl Desktop {
    pub(crate) fn show_start_in_results(&self) -> bool {
        self.snapshot.progress.status == ScanStatus::Idle && self.snapshot.results.is_empty()
    }

    pub(crate) fn toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let target = self.target.read(cx).value();
        let validation = target_count(&target);
        let busy = self.busy();
        let paused = self.snapshot.progress.status == ScanStatus::Paused;
        div()
            .px_5()
            .pt_4()
            .pb_3()
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(gpui_component::Icon::new(IconName::Globe).text_color(theme.primary))
                    .child(div().text_lg().font_bold().mr_3().child("PistonScan"))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(Input::new(&self.target).disabled(busy)),
                    )
                    .when(!self.show_start_in_results(), |row| row.child(
                        Button::new("scan")
                            .primary()
                            .label(if self.stopping {
                                "Stopping…".to_owned()
                            } else if busy {
                                "Stop".to_owned()
                            } else if self.confirm.as_deref() == Some(target.as_ref()) {
                                "Confirm scan".to_owned()
                            } else if validation.is_ok() {
                                format!("Scan {target}")
                            } else {
                                "Scan".to_owned()
                            })
                            .tooltip(if cfg!(target_os = "macos") {
                                "Start or stop scan (⌘R)"
                            } else {
                                "Start or stop scan (Ctrl+R)"
                            })
                            .disabled(self.stopping || (!busy && validation.is_err()))
                            .on_click(cx.listener(|view, _, _, cx| view.toggle_scan(cx))),
                    ))
                    .when(busy && !self.stopping, |row| {
                        row.child(
                            Button::new("pause")
                                .outline()
                                .label(if paused { "Resume" } else { "Pause" })
                                .on_click(cx.listener(move |view, _, _, _| {
                                    view.set_status(if paused {
                                        ScanStatus::Running
                                    } else {
                                        ScanStatus::Paused
                                    });
                                })),
                        )
                    })
                    .child(
                        Button::new("settings")
                            .outline()
                            .icon(IconName::Settings)
                            .tooltip("Scan settings")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.panel = (view.panel != Some(ToolbarPanel::Settings)).then_some(ToolbarPanel::Settings);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("files")
                            .outline()
                            .icon(IconName::Ellipsis)
                            .tooltip("Scan files")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.panel = (view.panel != Some(ToolbarPanel::Files)).then_some(ToolbarPanel::Files);
                                cx.notify();
                            })),
                    ),
            )
            .when(self.panel == Some(ToolbarPanel::Files), |bar| bar.child(self.file_menu(cx)))
            .when_some(self.interface.clone().filter(|_| !self.show_start_in_results()), |bar, label| bar.child(div().mt_2().text_xs().text_color(theme.muted_foreground).child(label)))
            .when(!busy, |bar| {
                bar.when_some(validation.err(), |bar, error| {
                    bar.child(div().mt_2().text_sm().text_color(theme.danger).child(if target.is_empty() && self.interface.is_none() { "No active IPv4 interface found. Connect to a network or enter an address." } else { error }))
                })
                .when(self.confirm.as_deref() == Some(target.as_ref()), |bar| {
                    let count = target_count(&target).unwrap_or_default();
                    let delay = self.delay.read(cx).value().parse::<u64>().unwrap_or_default();
                    let minutes = count.saturating_sub(1).saturating_mul(delay) / 60_000;
                    let estimate = if minutes == 0 {
                        "This can take several minutes.".to_owned()
                    } else {
                        format!("The configured delay alone takes at least {minutes} min.")
                    };
                    bar.child(div().mt_2().text_sm().child(format!("Scan {count} addresses? {estimate}")))
                })
            })
    }

    fn file_menu(&self, cx: &Context<Self>) -> impl IntoElement {
        div()
            .mt_2()
            .flex()
            .justify_end()
            .gap_2()
            .child(
                Button::new("import")
                    .label("Import JSON")
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.panel = None;
                        view.import(window, cx);
                        cx.notify();
                    })),
            )
            .child(
                Button::new("export")
                    .label("Export JSON")
                    .disabled(self.snapshot.results.is_empty())
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.panel = None;
                        view.export(cx);
                        cx.notify();
                    })),
            )
    }

    pub(crate) fn progress(&self, cx: &Context<Self>) -> impl IntoElement {
        let progress = &self.snapshot.progress;
        let status = status_message(
            progress.status,
            self.stopping,
            !self.error.is_empty(),
            target_count(&self.target.read(cx).value()).is_ok(),
        );
        let elapsed = self.elapsed.as_secs();
        let percent = progress
            .completed
            .saturating_mul(100)
            .checked_div(progress.total)
            .unwrap_or_default()
            .min(100);
        let remaining = elapsed
            .saturating_mul(progress.total.saturating_sub(progress.completed))
            .checked_div(progress.completed);
        let theme = cx.theme();
        div()
            .bg(theme.muted)
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .child(div().font_bold().child(status))
                    .when(progress.total > 0, |bar| {
                        bar.text_color(theme.muted_foreground)
                            .child(format!(
                                "{} of {} checked",
                                progress.completed, progress.total
                            ))
                            .child(format!("{} found", self.online))
                            .when(self.started.is_some(), |bar| {
                                bar.child(format!("{elapsed}s elapsed"))
                            })
                            .when_some(
                                remaining.filter(|_| {
                                    progress.status == ScanStatus::Running && !self.stopping
                                }),
                                |bar, seconds| bar.child(format!("About {seconds}s left")),
                            )
                    }),
            )
            .when(self.busy(), |bar| {
                bar.child(
                    gpui_component::progress::Progress::new()
                        .value(f32::from(u16::try_from(percent).unwrap_or_default()))
                        .h(px(3.)),
                )
            })
    }
}

fn status_message(status: ScanStatus, stopping: bool, error: bool, valid: bool) -> &'static str {
    if stopping {
        return "Stopping…";
    }
    match status {
        ScanStatus::Running => "Scanning",
        ScanStatus::Paused => "Paused",
        _ if error => "Check the error above",
        _ if !valid => "Fix the subnet to scan",
        ScanStatus::Idle => "Ready to scan",
        ScanStatus::Cancelled => "Scan cancelled",
        ScanStatus::Completed => "Scan complete",
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanStatus, status_message};

    #[test]
    fn status_follows_scan_and_target() {
        for (status, stopping, error, valid, expected) in [
            (ScanStatus::Idle, false, false, true, "Ready to scan"),
            (
                ScanStatus::Idle,
                false,
                false,
                false,
                "Fix the subnet to scan",
            ),
            (ScanStatus::Idle, false, true, true, "Check the error above"),
            (ScanStatus::Running, false, false, true, "Scanning"),
            (ScanStatus::Paused, false, false, true, "Paused"),
            (ScanStatus::Paused, true, false, true, "Stopping…"),
            (ScanStatus::Completed, false, false, true, "Scan complete"),
            (ScanStatus::Cancelled, false, false, true, "Scan cancelled"),
        ] {
            assert_eq!(
                status_message(status, stopping, error, valid),
                expected,
                "Unexpected message for {status:?}"
            );
        }
    }
}
