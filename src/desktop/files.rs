use std::path::PathBuf;

use gpui::{Context, PathPromptOptions, Window};

use crate::Desktop;
use pistonscan::snapshot::{ScanStatus, Snapshot};

impl Desktop {
    pub(crate) fn import(&self, window: &Window, cx: &Context<Self>) {
        let picker = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Choose a PistonScan JSON snapshot".into()),
        });
        let runtime = self.runtime.handle().clone();
        cx.spawn_in(window, async move |view, cx| {
            let result = async {
                let Some(path) = picker
                    .await
                    .map_err(|error| error.to_string())?
                    .map_err(|error| error.to_string())?
                    .and_then(|paths| paths.into_iter().next())
                else {
                    return Ok(None);
                };
                let snapshot = runtime
                    .spawn(async move {
                        let data = tokio::fs::read(path)
                            .await
                            .map_err(|error| error.to_string())?;
                        serde_json::from_slice::<Snapshot>(&data).map_err(|error| error.to_string())
                    })
                    .await
                    .map_err(|error| error.to_string())??;
                Ok::<_, String>(Some(snapshot))
            }
            .await;
            drop(view.update_in(cx, |view, window, cx| {
                match result {
                    Ok(Some(snapshot)) => view.apply_import(snapshot, window, cx),
                    Ok(None) => {}
                    Err(error) => view.error = error,
                }
                cx.notify();
            }));
        })
        .detach();
    }

    pub(crate) fn apply_import(
        &mut self,
        mut snapshot: Snapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_status(ScanStatus::Cancelled);
        self.control = None;
        self.stopping = false;
        self.scan_id = self.scan_id.wrapping_add(1);
        let count = snapshot.results.len() as u64;
        if snapshot.progress.total == 0 {
            snapshot.progress.total = count;
        }
        if snapshot.progress.completed == 0 {
            snapshot.progress.completed = count;
        }
        snapshot.progress.status = ScanStatus::Completed;
        snapshot.progress.active = 0;
        self.target.update(cx, |input, cx| {
            input.set_value(snapshot.config.subnet.clone(), window, cx);
        });
        self.threads.update(cx, |input, cx| {
            input.set_value(snapshot.config.thread_limit.to_string(), window, cx);
        });
        self.delay.update(cx, |input, cx| {
            input.set_value(snapshot.config.delay_ms.to_string(), window, cx);
        });
        self.snapshot = snapshot;
        self.online = self
            .snapshot
            .results
            .iter()
            .filter(|host| host.reachable)
            .count();
        self.started = None;
        self.selected = None;
        self.latest = None;
        self.update_visible(cx);
        self.error.clear();
    }

    pub(crate) fn export(&self, cx: &Context<Self>) {
        let mut snapshot = self.snapshot.clone();
        snapshot.updated = chrono::Utc::now().to_rfc3339();
        let name = format!(
            "pistonscan-{}.json",
            chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S")
        );
        let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let picker = cx.prompt_for_new_path(&directory, Some(&name));
        let runtime = self.runtime.handle().clone();
        cx.spawn(async move |view, cx| {
            let result = async {
                let Some(path) = picker
                    .await
                    .map_err(|error| error.to_string())?
                    .map_err(|error| error.to_string())?
                else {
                    return Ok(());
                };
                runtime
                    .spawn(async move {
                        let data = serde_json::to_vec_pretty(&snapshot)
                            .map_err(|error| error.to_string())?;
                        tokio::fs::write(path, data)
                            .await
                            .map_err(|error| error.to_string())
                    })
                    .await
                    .map_err(|error| error.to_string())?
            }
            .await;
            if let Err(error) = result {
                drop(view.update(cx, |view, cx| {
                    view.error = error;
                    cx.notify();
                }));
            }
        })
        .detach();
    }
}
