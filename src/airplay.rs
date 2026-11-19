use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;

use plist::Value;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::snapshot::ServiceInfo;

/// Device information dictionaries nest a few levels deep. `display` recurses once per level.
const MAX_DEPTH: usize = 16;

#[must_use]
pub fn should_query(services: &[ServiceInfo]) -> bool {
    services
        .iter()
        .any(|service| service.port == 7000 && service.protocol.eq_ignore_ascii_case("tcp"))
}

#[must_use]
pub fn parse_response(data: &[u8]) -> BTreeMap<String, String> {
    // Check the limits first, so a hostile response cannot build a value that overflows the stack.
    if plist::from_reader::<_, Bounded>(Cursor::new(data)).is_err() {
        return BTreeMap::new();
    }
    let Ok(Value::Dictionary(fields)) = Value::from_reader(Cursor::new(data)) else {
        return BTreeMap::new();
    };
    fields
        .into_iter()
        .filter_map(|(key, value)| {
            let text = display(&value);
            (!text.is_empty()).then_some((key, text))
        })
        .collect()
}

/// A property list that stays within `MAX_DEPTH`.
struct Bounded;

impl<'de> de::Deserialize<'de> for Bounded {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Limits { depth: 0 }.deserialize(deserializer)?;
        Ok(Self)
    }
}

#[derive(Clone, Copy)]
struct Limits {
    depth: usize,
}

impl Limits {
    fn child<E: de::Error>(self) -> Result<Self, E> {
        if self.depth < MAX_DEPTH {
            Ok(Self {
                depth: self.depth + 1,
            })
        } else {
            Err(E::custom("property list nests too deeply"))
        }
    }
}

impl<'de> DeserializeSeed<'de> for Limits {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Limits {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a property list value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let child = self.child()?;
        while seq.next_element_seed(child)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let child = self.child()?;
        while map.next_key_seed(child)?.is_some() {
            map.next_value_seed(child)?;
        }
        Ok(())
    }
}

fn display(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_owned(),
        Value::Boolean(value) => value.to_string(),
        Value::Integer(value) => value.to_string(),
        Value::Real(value) => value.to_string(),
        Value::Uid(value) => value.get().to_string(),
        Value::Date(value) => value.to_xml_format(),
        Value::Data(bytes) => {
            const DIGITS: &[u8] = b"0123456789ABCDEF";
            if let Ok(text) = std::str::from_utf8(bytes)
                && text
                    .chars()
                    .all(|c| c >= ' ' || matches!(c, '\n' | '\r' | '\t'))
            {
                return text.trim().to_owned();
            }
            let mut hex = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
                hex.push(char::from(DIGITS[usize::from(byte & 15)]));
            }
            hex
        }
        Value::Array(values) => values
            .iter()
            .map(display)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Value::Dictionary(entries) => entries
            .iter()
            .filter_map(|(key, value)| {
                let text = display(value);
                (!text.is_empty()).then(|| (key, format!("{key}={text}")))
            })
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "AirPlay queries use a separate bounded client for local HTTP endpoints"
)]
pub async fn fetch(ip: std::net::Ipv4Addr) -> Option<crate::snapshot::AirPlayInfo> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1500))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    for endpoint in ["info", "server-info"] {
        let Ok(mut response) = client
            .get(format!("http://{ip}:7000/{endpoint}"))
            .send()
            .await
        else {
            continue;
        };
        if response.status() != reqwest::StatusCode::OK {
            continue;
        }
        let mut data = Vec::new();
        let mut complete = false;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if data.len() + chunk.len() <= 1_048_576 => {
                    data.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    complete = true;
                    break;
                }
                Ok(Some(_)) | Err(_) => break,
            }
        }
        if complete {
            let fields = parse_response(&data);
            if !fields.is_empty() {
                return Some(crate::snapshot::AirPlayInfo {
                    endpoint: endpoint.to_owned(),
                    fields,
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{MAX_DEPTH, display, parse_response, should_query};
    use crate::snapshot::ServiceInfo;
    use plist::{Dictionary, Value};

    #[test]
    fn reads_airplay_dictionary() {
        let sample = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>deviceid</key><string>AA:BB:CC:DD:EE:FF</string>
    <key>model</key><string>AppleTV6,2</string>
    <key>features</key><integer>123456</integer>
</dict>
</plist>"#;
        let fields = parse_response(sample);
        assert_eq!(fields.len(), 3, "Three advertised fields");
        assert_eq!(
            fields.get("deviceid").map(String::as_str),
            Some("AA:BB:CC:DD:EE:FF"),
            "Preserve the device identifier"
        );
        assert_eq!(
            fields.get("model").map(String::as_str),
            Some("AppleTV6,2"),
            "Preserve the model identifier"
        );
        assert_eq!(
            fields.get("features").map(String::as_str),
            Some("123456"),
            "Format the feature bitmask"
        );
    }

    #[test]
    fn rejects_deeply_nested_values() {
        let nested = |depth| {
            format!(
                "<plist><dict><key>a</key>{}<string>x</string>{}</dict></plist>",
                "<array>".repeat(depth),
                "</array>".repeat(depth)
            )
        };
        assert_eq!(
            parse_response(nested(MAX_DEPTH - 1).as_bytes())
                .get("a")
                .map(String::as_str),
            Some("x"),
            "Accept nesting up to the limit"
        );
        assert!(
            parse_response(nested(MAX_DEPTH).as_bytes()).is_empty(),
            "Reject nesting beyond the limit"
        );
        // A 900 KB response that overflowed the stack in `display`.
        assert!(
            parse_response(nested(60_000).as_bytes()).is_empty(),
            "Reject a response that nests 60000 arrays"
        );
    }

    #[test]
    fn triggers_only_for_tcp_airplay() {
        let mut service = ServiceInfo {
            port: 7000,
            protocol: "tcp".to_owned(),
            ..ServiceInfo::default()
        };
        assert!(
            should_query(std::slice::from_ref(&service)),
            "Query TCP port 7000"
        );
        service.protocol = "udp".to_owned();
        assert!(!should_query(&[service]), "Skip UDP port 7000");
    }

    #[test]
    fn formats_data_and_nested_entries() {
        let dict = Dictionary::from_iter([
            ("name", Value::String("AirPlay".to_owned())),
            ("active", Value::Boolean(true)),
        ]);
        assert_eq!(
            display(&Value::Data(b"Test String".to_vec())),
            "Test String",
            "Printable data stays text"
        );
        assert_eq!(
            display(&Value::Data(vec![0, 1, 2])),
            "000102",
            "Binary data becomes hex"
        );
        assert_eq!(
            display(&Value::Dictionary(dict)),
            "active=true, name=AirPlay",
            "Sort nested fields by key"
        );
    }
}
