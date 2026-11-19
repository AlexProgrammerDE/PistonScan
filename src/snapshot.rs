use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    #[default]
    Idle,
    Running,
    Paused,
    Cancelled,
    Completed,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    pub subnet: String,
    pub thread_limit: u64,
    pub delay_ms: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HostResult {
    pub ip: String,
    pub reachable: bool,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub latency_samples: Vec<f64>,
    pub attempts: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub ttl: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mdns_names: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub netbios_names: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub llmnr_names: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smb_info: Option<SmbInfo>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mac_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub manufacturer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub os_guess: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub air_play: Option<AirPlayInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub discovery_sources: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub insight_score: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ServiceInfo {
    pub port: u64,
    pub protocol: String,
    pub service: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub banner: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_cert_info: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AirPlayInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SmbInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub computer_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Progress {
    pub total: u64,
    pub completed: u64,
    pub active: u64,
    pub status: ScanStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Snapshot {
    pub config: Config,
    pub progress: Progress,
    pub results: Vec<HostResult>,
    pub updated: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Update {
    pub result: HostResult,
    pub progress: Progress,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde passes the field by reference"
)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::{ScanStatus, Snapshot};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions report snapshot compatibility failures"
    )]
    fn reads_legacy_snapshot_fields() -> Result<(), serde_json::Error> {
        let snapshot: Snapshot = serde_json::from_str(
            r#"{
            "config":{"subnet":"192.0.2.1","threadLimit":64,"delayMs":10},
            "progress":{"total":1,"completed":1,"active":0,"status":"completed"},
            "results":[{"ip":"192.0.2.1","reachable":true,"latencyMs":1.5,"attempts":3,
            "smbInfo":{"computerName":"PC"},"airPlay":{"fields":{"model":"AppleTV"}}}],
            "updated":"2026-01-01T00:00:00Z"
        }"#,
        )?;
        assert_eq!(snapshot.config.thread_limit, 64, "Decode camelCase input");
        assert_eq!(
            snapshot.progress.status,
            ScanStatus::Completed,
            "Decode the scan status"
        );
        let host = &snapshot.results[0];
        assert_eq!(
            host.smb_info
                .as_ref()
                .map(|info| info.computer_name.as_str()),
            Some("PC"),
            "Keep the workstation name"
        );
        let round_trip = serde_json::to_value(snapshot)?;
        assert_eq!(
            round_trip["results"][0]["airPlay"]["fields"]["model"], "AppleTV",
            "Keep the legacy AirPlay property name"
        );
        Ok(())
    }
}
