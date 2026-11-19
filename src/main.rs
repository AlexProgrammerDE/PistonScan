#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod desktop;

use std::collections::BTreeSet;

use desktop::results::Sort;
use gpui::{
    AppContext, Application, Bounds, Context, Entity, TitlebarOptions, Window, WindowBounds,
    WindowOptions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Disableable, Root, Theme, ThemeMode,
    button::{Button, ButtonVariants},
    input::{Input, InputState},
};
use pistonscan::{
    manager::{Scan, ScanEvent},
    ping,
    snapshot::{Config, ScanStatus, Snapshot},
};
use tokio::runtime::Runtime;
use tokio::sync::watch;

struct Desktop {
    runtime: Runtime,
    target: Entity<InputState>,
    threads: Entity<InputState>,
    delay: Entity<InputState>,
    snapshot: Snapshot,
    control: Option<watch::Sender<ScanStatus>>,
    scan_id: u64,
    error: String,
    expanded: BTreeSet<String>,
    reachable_only: bool,
    successful_only: bool,
    minimum: u64,
    sort: Sort,
}

impl Desktop {
    fn busy(&self) -> bool {
        matches!(
            self.snapshot.progress.status,
            ScanStatus::Running | ScanStatus::Paused
        )
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        let (Ok(thread_limit), Ok(delay_ms)) = (
            self.threads.read(cx).value().parse(),
            self.delay.read(cx).value().parse(),
        ) else {
            self.error = "Enter whole numbers for threads and delay.".into();
            cx.notify();
            return;
        };
        let config = Config {
            subnet: self.target.read(cx).value().to_string(),
            thread_limit,
            delay_ms,
        };
        let scan = {
            let _runtime = self.runtime.enter();
            Scan::start(&config, ping::collect)
        };
        let Scan {
            control,
            mut events,
        } = match scan {
            Ok(scan) => scan,
            Err(error) => {
                self.error = error.to_string();
                cx.notify();
                return;
            }
        };
        self.error.clear();
        self.expanded.clear();
        self.minimum = 0;
        self.snapshot = Snapshot {
            config,
            ..Snapshot::default()
        };
        self.snapshot.progress.status = ScanStatus::Running;
        self.control = Some(control);
        self.scan_id = self.scan_id.wrapping_add(1);
        let scan_id = self.scan_id;
        cx.spawn(async move |view, cx| {
            while let Some(event) = events.recv().await {
                let active = view.update(cx, |view, cx| {
                    if view.scan_id != scan_id {
                        return false;
                    }
                    view.snapshot.progress = match event {
                        ScanEvent::Host(host, progress) => {
                            view.snapshot.results.push(*host);
                            progress
                        }
                        ScanEvent::Progress(progress) => progress,
                    };
                    cx.notify();
                    view.busy()
                });
                if !matches!(active, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn set_status(&self, status: ScanStatus) {
        if let Some(control) = &self.control {
            control.send_replace(status);
        }
    }

    fn controls(&self, cx: &Context<Self>) -> impl IntoElement {
        let status = self.snapshot.progress.status;
        let busy = self.busy();
        div()
            .flex()
            .items_end()
            .gap_3()
            .child(
                div()
                    .flex_1()
                    .child("Subnet / IP")
                    .child(Input::new(&self.target)),
            )
            .child(
                div()
                    .w_20()
                    .child("Threads")
                    .child(Input::new(&self.threads)),
            )
            .child(
                div()
                    .w_24()
                    .child("Delay (ms)")
                    .child(Input::new(&self.delay)),
            )
            .child(
                Button::new("start")
                    .label("Start Scan")
                    .primary()
                    .disabled(busy)
                    .on_click(cx.listener(|view, _, _, cx| view.start(cx))),
            )
            .child(
                Button::new("pause")
                    .label("Pause")
                    .disabled(status != ScanStatus::Running)
                    .on_click(cx.listener(|view, _, _, _| view.set_status(ScanStatus::Paused))),
            )
            .child(
                Button::new("resume")
                    .label("Resume")
                    .disabled(status != ScanStatus::Paused)
                    .on_click(cx.listener(|view, _, _, _| view.set_status(ScanStatus::Running))),
            )
            .child(
                Button::new("cancel")
                    .label("Cancel")
                    .disabled(!busy)
                    .on_click(cx.listener(|view, _, _, _| view.set_status(ScanStatus::Cancelled))),
            )
    }
}

impl Render for Desktop {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let status = self.snapshot.progress.status;
        let progress = &self.snapshot.progress;
        let percent = progress
            .completed
            .saturating_mul(100)
            .saturating_add(progress.total / 2)
            .checked_div(progress.total)
            .unwrap_or_default()
            .min(100);
        let percent_bar = f32::from(u16::try_from(percent).unwrap_or_default());
        let reachable = self
            .snapshot
            .results
            .iter()
            .filter(|host| host.reachable)
            .count();
        let summary = format!(
            "{status:?}    {} / {} complete    {} active    {reachable} reachable    {percent}%",
            progress.completed, progress.total, progress.active
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_4()
            .p_5()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(div().text_xl().child("PistonScan"))
            .child(self.controls(cx))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(div().text_color(theme.muted_foreground).child(summary))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("export")
                                    .label("Export")
                                    .disabled(self.snapshot.results.is_empty())
                                    .on_click(cx.listener(|view, _, _, cx| view.export(cx))),
                            )
                            .child(Button::new("import").label("Import").on_click(
                                cx.listener(|view, _, window, cx| view.import(window, cx)),
                            )),
                    ),
            )
            .when(!self.error.is_empty(), |view| {
                view.child(div().text_color(theme.danger).child(self.error.clone()))
            })
            .child(
                gpui_component::progress::Progress::new()
                    .value(percent_bar)
                    .h(px(4.)),
            )
            .child(self.results(cx))
    }
}

fn main() {
    let runtime = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Cannot start the scan runtime: {error}");
            return;
        }
    };
    Application::new()
        .with_assets(gpui_component_assets::Assets)
        .run(move |cx| {
            gpui_component::init(cx);
            Theme::change(ThemeMode::Light, None, cx);
            let theme = cx.global_mut::<Theme>();
            theme.radius = px(5.);
            theme.colors.primary = gpui::rgb(0x2458a4).into();
            theme.colors.primary_hover = gpui::rgb(0x1e4988).into();
            theme.colors.primary_active = gpui::rgb(0x173a6e).into();
            theme.colors.progress_bar = theme.colors.primary;
            theme.colors.ring = theme.colors.primary;

            cx.on_window_closed(|cx| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(1024.), px(768.)),
                    cx,
                ))),
                titlebar: Some(TitlebarOptions {
                    title: Some("PistonScan".into()),
                    ..TitlebarOptions::default()
                }),
                ..WindowOptions::default()
            };
            if let Err(error) = cx.open_window(options, move |window, cx| {
                let desktop = cx.new(|cx| Desktop {
                    runtime,
                    target: cx
                        .new(|cx| InputState::new(window, cx).default_value("192.168.1.0/24")),
                    threads: cx.new(|cx| InputState::new(window, cx).default_value("64")),
                    delay: cx.new(|cx| InputState::new(window, cx).default_value("10")),
                    snapshot: Snapshot::default(),
                    control: None,
                    scan_id: 0,
                    error: String::new(),
                    expanded: BTreeSet::new(),
                    reachable_only: true,
                    successful_only: false,
                    minimum: 0,
                    sort: Sort::default(),
                });
                cx.new(|cx| Root::new(desktop, window, cx))
            }) {
                eprintln!("Cannot open the PistonScan window: {error}");
                cx.quit();
            }
            cx.activate(true);
        });
}
