use std::future::Future;
use std::net::Ipv4Addr;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

use crate::snapshot::{Config, HostResult, Progress, ScanStatus};
use crate::targets::{InvalidTarget, Targets};

#[derive(Debug, Error)]
pub enum StartError {
    #[error(transparent)]
    Target(#[from] InvalidTarget),
    #[error("Threads must be a positive number.")]
    Threads,
    #[error("The scan delay is too large.")]
    Delay,
}

pub enum ScanEvent {
    Progress(Progress),
    Host(Box<HostResult>, Progress),
}

pub struct Scan {
    pub control: watch::Sender<ScanStatus>,
    pub events: mpsc::Receiver<ScanEvent>,
}

impl Scan {
    /// Starts a scan on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid subnet, worker count, or launch delay.
    pub fn start<F, Fut>(config: &Config, collect: F) -> Result<Self, StartError>
    where
        F: Fn(Ipv4Addr) -> Fut + Send + 'static,
        Fut: Future<Output = HostResult> + Send + 'static,
    {
        let targets = Targets::parse(&config.subnet)?;
        let limit = usize::try_from(config.thread_limit)
            .ok()
            .filter(|limit| *limit > 0)
            .ok_or(StartError::Threads)?;
        let delay = Duration::from_millis(config.delay_ms);
        Instant::now().checked_add(delay).ok_or(StartError::Delay)?;
        let (control, commands) = watch::channel(ScanStatus::Running);
        let (output, events) = mpsc::channel(64);
        drop(tokio::spawn(run(
            targets, limit, delay, commands, output, collect,
        )));
        Ok(Self { control, events })
    }
}

async fn run<F, Fut>(
    targets: Targets,
    limit: usize,
    delay: Duration,
    mut control: watch::Receiver<ScanStatus>,
    output: mpsc::Sender<ScanEvent>,
    collect: F,
) where
    F: Fn(Ipv4Addr) -> Fut,
    Fut: Future<Output = HostResult> + Send + 'static,
{
    let mut progress = Progress {
        total: targets.count(),
        status: ScanStatus::Running,
        ..Progress::default()
    };
    let mut targets = targets.addresses().peekable();
    let mut workers = JoinSet::new();
    let mut next_launch = Instant::now();
    if output
        .send(ScanEvent::Progress(progress.clone()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        if workers.is_empty() && targets.peek().is_none() {
            progress.status = ScanStatus::Completed;
            break;
        }
        let can_launch = progress.status == ScanStatus::Running
            && workers.len() < limit
            && targets.peek().is_some();
        let event = tokio::select! {
            biased;
            changed = control.changed() => {
                if changed.is_err() {
                    return;
                }
                progress.status = *control.borrow_and_update();
                if progress.status == ScanStatus::Cancelled {
                    workers.shutdown().await;
                    progress.active = 0;
                    break;
                }
                ScanEvent::Progress(progress.clone())
            }
            finished = workers.join_next(), if !workers.is_empty() => {
                progress.active -= 1;
                progress.completed += 1;
                match finished {
                    Some(Ok(host)) => ScanEvent::Host(Box::new(host), progress.clone()),
                    _ => ScanEvent::Progress(progress.clone()),
                }
            }
            () = sleep_until(next_launch), if can_launch => {
                if let Some(ip) = targets.next() {
                    workers.spawn(collect(ip));
                    progress.active += 1;
                    next_launch = Instant::now().checked_add(delay).unwrap_or_else(Instant::now);
                }
                ScanEvent::Progress(progress.clone())
            }
        };
        if output.send(event).await.is_err() {
            return;
        }
    }
    drop(output.send(ScanEvent::Progress(progress)).await);
}

#[cfg(test)]
mod tests {
    use super::{Scan, ScanEvent, StartError};
    use crate::snapshot::{Config, HostResult, ScanStatus};

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions report lifecycle mismatches"
    )]
    async fn streams_each_host_before_completion() -> Result<(), StartError> {
        let config = Config {
            subnet: "192.0.2.0/30".into(),
            thread_limit: 2,
            delay_ms: 0,
        };
        let Scan {
            control,
            mut events,
        } = Scan::start(&config, |ip| async move {
            HostResult {
                ip: ip.to_string(),
                ..HostResult::default()
            }
        })?;
        let mut hosts = Vec::new();
        let mut final_status = ScanStatus::Idle;
        while let Some(event) = events.recv().await {
            match event {
                ScanEvent::Host(host, progress) => {
                    hosts.push(host.ip);
                    assert!(progress.active <= 2, "Active workers exceeded the limit");
                    assert_eq!(
                        progress.completed,
                        hosts.len() as u64,
                        "Progress disagrees with results"
                    );
                }
                ScanEvent::Progress(progress) => final_status = progress.status,
            }
        }
        drop(control);
        hosts.sort_unstable();
        assert_eq!(
            hosts,
            ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"],
            "Every target must be reported"
        );
        assert_eq!(
            final_status,
            ScanStatus::Completed,
            "The final event must mark completion"
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions report lifecycle mismatches"
    )]
    async fn pauses_scheduling_and_cancels_active_work() -> Result<(), StartError> {
        let config = Config {
            subnet: "192.0.2.0/30".into(),
            thread_limit: 1,
            delay_ms: 0,
        };
        let Scan {
            control,
            mut events,
        } = Scan::start(&config, |_ip| std::future::pending())?;
        while let Some(event) = events.recv().await {
            if matches!(event, ScanEvent::Progress(progress) if progress.active == 1) {
                break;
            }
        }
        control.send_replace(ScanStatus::Paused);
        assert!(
            matches!(events.recv().await, Some(ScanEvent::Progress(progress))
            if progress.status == ScanStatus::Paused && progress.active == 1),
            "Pause preserves in-flight work"
        );
        control.send_replace(ScanStatus::Running);
        assert!(
            matches!(events.recv().await, Some(ScanEvent::Progress(progress))
            if progress.status == ScanStatus::Running && progress.active == 1),
            "Resume restores scheduling"
        );
        control.send_replace(ScanStatus::Cancelled);
        assert!(
            matches!(events.recv().await, Some(ScanEvent::Progress(progress))
            if progress.status == ScanStatus::Cancelled && progress.active == 0 && progress.completed == 0),
            "Cancel stops the worker and reports final progress"
        );
        assert!(
            events.recv().await.is_none(),
            "Cancel closes the event stream"
        );
        Ok(())
    }

    #[test]
    fn validates_config_before_starting_workers() {
        let config = Config {
            subnet: "192.0.2.1".into(),
            ..Config::default()
        };
        assert!(
            matches!(
                Scan::start(&config, |_| std::future::pending()),
                Err(StartError::Threads)
            ),
            "Reject zero workers"
        );
        let bad_subnet = Config {
            subnet: "invalid".into(),
            thread_limit: 1,
            delay_ms: 0,
        };
        assert!(
            matches!(
                Scan::start(&bad_subnet, |_| std::future::pending()),
                Err(StartError::Target(_))
            ),
            "Reject malformed subnet"
        );
    }
}
