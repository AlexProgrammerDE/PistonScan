#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod desktop;

use std::time::{Duration, Instant};

use desktop::{
    settings::{self, Preferences},
    state::{self, Filter, Sort},
};
use gpui::{
    AppContext, Application, Bounds, Context, Entity, FocusHandle, KeyBinding, TitlebarOptions,
    UniformListScrollHandle, Window, WindowBounds, WindowOptions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Root,
    input::{InputEvent, InputState},
};
use pistonscan::{
    manager::{Scan, ScanEvent},
    ping,
    snapshot::{Config, ScanStatus, Snapshot},
};
use tokio::runtime::Runtime;
use tokio::sync::watch;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct FindDevices;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct ToggleScan;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct ExportScan;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct PreviousDevice;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct NextDevice;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct OpenDevice;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct Dismiss;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct ImportScan;

#[derive(Clone, PartialEq, Eq, gpui::Action)]
#[action(namespace = scanner)]
struct Quit;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ToolbarPanel {
    Settings,
    Files,
}

struct Desktop {
    runtime: Runtime,
    target: Entity<InputState>,
    threads: Entity<InputState>,
    delay: Entity<InputState>,
    snapshot: Snapshot,
    control: Option<watch::Sender<ScanStatus>>,
    scan_id: u64,
    error: String,
    selected: Option<String>,
    inspector: bool,
    raw: bool,
    filter: Filter,
    sort: Sort,
    visible: Vec<usize>,
    scroll: UniformListScrollHandle,
    search: Entity<InputState>,
    panel: Option<ToolbarPanel>,
    confirm: Option<String>,
    focus: FocusHandle,
    started: Option<Instant>,
    elapsed: Duration,
    online: usize,
    interface: Option<String>,
    window_size: Option<(f32, f32)>,
    probes: ping::ProbeGroups,
    columns: [f32; 3],
    resize_start: Option<(gpui::Pixels, f32)>,
    latest: Option<(usize, Instant)>,
}

impl Desktop {
    fn busy(&self) -> bool {
        matches!(
            self.snapshot.progress.status,
            ScanStatus::Running | ScanStatus::Paused
        )
    }

    fn move_selection(&mut self, down: bool, cx: &mut Context<Self>) {
        let position = self
            .selected
            .as_ref()
            .and_then(|ip| state::selected_row(&self.snapshot.results, &self.visible, ip));
        let row = position.map_or(0, |row| {
            if down {
                row.saturating_add(1)
                    .min(self.visible.len().saturating_sub(1))
            } else {
                row.saturating_sub(1)
            }
        });
        if let Some(index) = self.visible.get(row) {
            self.selected = Some(self.snapshot.results[*index].ip.clone());
            self.raw = false;
            self.scroll
                .scroll_to_item(row, gpui::ScrollStrategy::Center);
            cx.notify();
        }
    }

    fn toggle_scan(&mut self, cx: &mut Context<Self>) {
        if self.busy() {
            self.set_status(ScanStatus::Cancelled);
            return;
        }
        self.start(cx);
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        let target = self.target.read(cx).value().to_string();
        let count = match state::target_count(&target) {
            Ok(count) => count,
            Err(error) => {
                self.error = error.into();
                cx.notify();
                return;
            }
        };
        if count > 1024 && self.confirm.as_ref() != Some(&target) {
            self.confirm = Some(target);
            cx.notify();
            return;
        }
        let (Ok(thread_limit), Ok(delay_ms)) = (
            self.threads.read(cx).value().parse(),
            self.delay.read(cx).value().parse(),
        ) else {
            self.error = "Enter whole numbers for threads and delay.".into();
            cx.notify();
            return;
        };
        let config = Config {
            subnet: target,
            thread_limit,
            delay_ms,
        };
        if !(1..=256).contains(&config.thread_limit) || config.delay_ms > 60_000 {
            self.error = "Use 1 to 256 concurrent checks and a delay of 0 to 60,000 ms.".into();
            self.panel = Some(ToolbarPanel::Settings);
            cx.notify();
            return;
        }
        let groups = self.probes;
        let scan = {
            let _runtime = self.runtime.enter();
            Scan::start(&config, move |ip| ping::collect_with(ip, groups))
        };
        let Scan { control, events } = match scan {
            Ok(scan) => scan,
            Err(error) => {
                self.error = error.to_string();
                cx.notify();
                return;
            }
        };
        self.error.clear();
        self.confirm = None;
        self.selected = None;
        self.visible.clear();
        self.online = 0;
        self.latest = None;
        self.started = Some(Instant::now());
        self.elapsed = Duration::ZERO;
        self.save(cx);
        self.snapshot = Snapshot {
            config,
            ..Snapshot::default()
        };
        self.snapshot.progress.status = ScanStatus::Running;
        self.snapshot.progress.total = count;
        self.control = Some(control);
        self.scan_id = self.scan_id.wrapping_add(1);
        let scan_id = self.scan_id;
        Self::consume_events(scan_id, events, cx);
        cx.notify();
    }

    fn consume_events(
        scan_id: u64,
        mut events: tokio::sync::mpsc::Receiver<ScanEvent>,
        cx: &Context<Self>,
    ) {
        cx.spawn(async move |view, cx| {
            while let Some(first) = events.recv().await {
                cx.background_executor().timer(Duration::from_millis(60)).await;
                let active = view.update(cx, |view, cx| {
                    if view.scan_id != scan_id {
                        return false;
                    }
                    let first_new = view.snapshot.results.len();
                    let mut event = Some(first);
                    let mut changed = false;
                    let mut ping_error = false;
                    while let Some(next) = event {
                        view.snapshot.progress = match next {
                            ScanEvent::Host(host, progress) => {
                                view.online += usize::from(host.reachable);
                                ping_error |= host.error.to_lowercase().contains("permission");
                                view.snapshot.results.push(*host);
                                changed = true;
                                progress
                            }
                            ScanEvent::Progress(progress) => progress,
                        };
                        event = events.try_recv().ok();
                    }
                    if ping_error {
                        view.error = "A network check was denied. Check that your system allows PistonScan to run ping.".into();
                    }
                    if let Some(started) = view.started {
                        view.elapsed = started.elapsed();
                    }
                    if changed {
                        let found = Instant::now();
                        view.latest = Some((first_new, found));
                        view.refresh_stream(first_new, cx);
                        cx.spawn(async move |view, cx| {
                            cx.background_executor().timer(Duration::from_millis(650)).await;
                            drop(view.update(cx, |view, cx| {
                                if view.latest.is_some_and(|(_, time)| time == found) {
                                    view.latest = None;
                                    cx.notify();
                                }
                            }));
                        }).detach();
                    }
                    cx.notify();
                    view.busy()
                });
                if !matches!(active, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
    }

    fn set_status(&self, status: ScanStatus) {
        if let Some(control) = &self.control {
            control.send_replace(status);
        }
    }
}

impl Render for Desktop {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        div()
            .id("pistonscan")
            .key_context("PistonScan")
            .track_focus(&self.focus)
            .on_action(cx.listener(|view, _: &FindDevices, window, cx| {
                view.search.update(cx, |input, cx| input.focus(window, cx));
            }))
            .on_action(cx.listener(|view, _: &ToggleScan, _, cx| view.toggle_scan(cx)))
            .on_action(cx.listener(|view, _: &ImportScan, window, cx| view.import(window, cx)))
            .on_action(cx.listener(|view, _: &ExportScan, _, cx| {
                if !view.snapshot.results.is_empty() {
                    view.export(cx);
                }
            }))
            .on_action(
                cx.listener(|view, _: &PreviousDevice, _, cx| view.move_selection(false, cx)),
            )
            .on_action(cx.listener(|view, _: &NextDevice, _, cx| view.move_selection(true, cx)))
            .on_action(cx.listener(|view, _: &OpenDevice, _, cx| {
                view.inspector = view.selected.is_some();
                cx.notify();
            }))
            .on_action(cx.listener(|view, _: &Dismiss, window, cx| {
                if view.search.read(cx).value().is_empty() {
                    view.inspector = false;
                    view.panel = None;
                    window.focus(&view.focus);
                } else {
                    view.search
                        .update(cx, |input, cx| input.set_value("", window, cx));
                }
                cx.notify();
            }))
            .size_full()
            .flex()
            .flex_col()
            .overflow_hidden()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(self.toolbar(cx))
            .when(self.panel == Some(ToolbarPanel::Settings), |app| {
                app.child(self.settings(cx))
            })
            .when(!self.error.is_empty(), |app| {
                app.child(
                    div()
                        .px_5()
                        .py_2()
                        .text_sm()
                        .text_color(theme.danger)
                        .child(self.error.clone()),
                )
            })
            .child(self.progress(cx))
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
            let modifier = if cfg!(target_os = "macos") {
                "cmd"
            } else {
                "ctrl"
            };
            cx.bind_keys([
                KeyBinding::new(&format!("{modifier}-f"), FindDevices, Some("PistonScan")),
                KeyBinding::new(&format!("{modifier}-r"), ToggleScan, Some("PistonScan")),
                KeyBinding::new(&format!("{modifier}-enter"), ToggleScan, Some("PistonScan")),
                KeyBinding::new(&format!("{modifier}-e"), ExportScan, Some("PistonScan")),
                KeyBinding::new("up", PreviousDevice, Some("PistonScan && !Input")),
                KeyBinding::new("down", NextDevice, Some("PistonScan && !Input")),
                KeyBinding::new("enter", OpenDevice, Some("PistonScan && !Input")),
                KeyBinding::new("space", OpenDevice, Some("PistonScan && !Input")),
                KeyBinding::new("escape", Dismiss, Some("PistonScan")),
            ]);

            if cfg!(target_os = "macos") {
                install_menu(cx);
            }
            cx.on_window_closed(|cx| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            let prefs = Preferences::load(&runtime);
            let (width, height) = prefs.window_size.map_or((1110., 740.), |(w, h)| {
                (w.clamp(820., 3840.), h.clamp(460., 2160.))
            });
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(width), px(height)),
                    cx,
                ))),
                window_min_size: Some(size(px(820.), px(460.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("PistonScan".into()),
                    ..TitlebarOptions::default()
                }),
                ..WindowOptions::default()
            };
            if let Err(error) = cx.open_window(options, move |window, cx| {
                let desktop = create_desktop(runtime, prefs, window, cx);
                open_startup_snapshot(&desktop, window, cx);
                cx.new(|cx| Root::new(desktop, window, cx))
            }) {
                eprintln!("Cannot open the PistonScan window: {error}");
                cx.quit();
            }
            cx.activate(true);
        });
}

fn create_desktop(
    runtime: Runtime,
    prefs: Preferences,
    window: &mut Window,
    cx: &mut gpui::App,
) -> Entity<Desktop> {
    desktop::theme::synchronize(window, cx);
    window
        .observe_window_appearance(desktop::theme::synchronize)
        .detach();
    let local = settings::local_target();
    let target = if prefs.target.is_empty() {
        local.as_ref().map_or_default(|(_, target)| target.clone())
    } else {
        prefs.target
    };
    cx.new(|cx: &mut Context<Desktop>| {
        let target = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("IPv4 address or subnet")
                .default_value(target)
        });
        let threads = cx.new(|cx| {
            InputState::new(window, cx).default_value(if prefs.threads.is_empty() {
                "64".into()
            } else {
                prefs.threads
            })
        });
        let delay = cx.new(|cx| {
            InputState::new(window, cx).default_value(if prefs.delay.is_empty() {
                "10".into()
            } else {
                prefs.delay
            })
        });
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search devices"));
        cx.subscribe_in(&search, window, |view, _, event: &InputEvent, _, cx| {
            if matches!(event, InputEvent::Change) {
                view.update_visible(cx);
                cx.notify();
            }
        })
        .detach();
        for input in [&target, &threads, &delay] {
            cx.subscribe_in(input, window, |view, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    view.confirm = None;
                    view.error.clear();
                    cx.notify();
                }
                if matches!(event, InputEvent::Blur) {
                    view.save(cx);
                }
            })
            .detach();
        }
        cx.observe_window_bounds(window, |view, window, cx| {
            if let WindowBounds::Windowed(bounds) = window.window_bounds() {
                view.window_size = Some((bounds.size.width.into(), bounds.size.height.into()));
                view.save(cx);
            }
        })
        .detach();
        let focus = cx.focus_handle();
        window.focus(&focus);
        Desktop {
            runtime,
            target,
            threads,
            delay,
            search,
            focus,
            snapshot: Snapshot::default(),
            control: None,
            scan_id: 0,
            error: String::new(),
            selected: None,
            inspector: false,
            raw: false,
            filter: prefs.filter,
            sort: prefs.sort,
            visible: Vec::new(),
            scroll: UniformListScrollHandle::new(),
            panel: None,
            confirm: None,
            started: None,
            elapsed: Duration::ZERO,
            online: 0,
            interface: local.map(|(label, _)| label),
            window_size: prefs.window_size,
            probes: prefs.probes,
            columns: [
                prefs.columns[0].clamp(104., 130.),
                prefs.columns[1].clamp(82., 100.),
                prefs.columns[2].clamp(100., 130.),
            ],
            resize_start: None,
            latest: None,
        }
    })
}

fn open_startup_snapshot(desktop: &Entity<Desktop>, window: &mut Window, cx: &mut gpui::App) {
    if let Some(path) = std::env::args_os().nth(1) {
        let snapshot = desktop
            .read(cx)
            .runtime
            .block_on(tokio::fs::read(path))
            .map_err(|error| error.to_string())
            .and_then(|data| serde_json::from_slice(&data).map_err(|error| error.to_string()));
        desktop.update(cx, |view, cx| match snapshot {
            Ok(snapshot) => view.apply_import(snapshot, window, cx),
            Err(error) => view.error = format!("Could not open scan snapshot. {error}"),
        });
    }
    #[cfg(debug_assertions)]
    desktop.update(cx, |view, cx| {
        let preview = std::env::var("PISTONSCAN_PREVIEW");
        if let Ok(state) = &preview {
            let target = if state == "error" {
                "192.0.2.0/39"
            } else {
                "192.0.2.0/24"
            };
            view.interface = Some("Ethernet · 192.0.2.100/24".into());
            view.target
                .update(cx, |input, cx| input.set_value(target, window, cx));
        }
        match preview.as_deref() {
            Ok("settings") => view.panel = Some(ToolbarPanel::Settings),
            Ok("inspector") => {
                view.selected = view.snapshot.results.first().map(|host| host.ip.clone());
                view.inspector = true;
            }
            Ok("scanning") => {
                view.snapshot.progress.status = ScanStatus::Running;
                view.snapshot.progress.total = 256;
                view.snapshot.progress.completed = 73;
                view.started = Some(Instant::now());
                view.elapsed = Duration::from_secs(7);
            }
            _ => {}
        }
    });
}

fn install_menu(cx: &mut gpui::App) {
    use gpui::{Menu, MenuItem};
    cx.on_action(|_: &Quit, cx| cx.quit());
    cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
    cx.set_menus(vec![
        Menu {
            name: "PistonScan".into(),
            items: vec![MenuItem::action("Quit PistonScan", Quit)],
        },
        Menu {
            name: "Scan".into(),
            items: vec![
                MenuItem::action("Start or stop scan", ToggleScan),
                MenuItem::action("Find devices", FindDevices),
                MenuItem::separator(),
                MenuItem::action("Import JSON", ImportScan),
                MenuItem::action("Export JSON", ExportScan),
            ],
        },
    ]);
}
