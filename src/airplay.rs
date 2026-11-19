use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;

use plist::Value;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::snapshot::ServiceInfo;

/// Device information dictionaries nest a few levels deep. `display` recurses once per level.
const MAX_DEPTH: usize = 16;
/// `fetch` reads at most this many bytes of a response body.
const MAX_RESPONSE_BYTES: usize = 1_048_576;

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

/// A property list that stays within `MAX_DEPTH` and does not expand beyond `MAX_RESPONSE_BYTES`.
///
/// A binary property list can reference one object many times, and the reader copies the object
/// for each reference. A few hundred bytes can expand to more values than fit in memory.
struct Bounded;

impl<'de> de::Deserialize<'de> for Bounded {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let budget = Cell::new(MAX_RESPONSE_BYTES);
        Limits {
            depth: 0,
            budget: &budget,
        }
        .deserialize(deserializer)?;
        Ok(Self)
    }
}

#[derive(Clone, Copy)]
struct Limits<'a> {
    depth: usize,
    /// Bytes left. Each value costs one byte, plus the length of a string or data value.
    budget: &'a Cell<usize>,
}

impl Limits<'_> {
    fn charge<E: de::Error>(self, length: usize) -> Result<(), E> {
        let remaining = self
            .budget
            .get()
            .checked_sub(length.saturating_add(1))
            .ok_or_else(|| E::custom("property list expands beyond the response limit"))?;
        self.budget.set(remaining);
        Ok(())
    }

    fn child<E: de::Error>(self) -> Result<Self, E> {
        self.charge(0)?;
        if self.depth < MAX_DEPTH {
            Ok(Self {
                depth: self.depth + 1,
                budget: self.budget,
            })
        } else {
            Err(E::custom("property list nests too deeply"))
        }
    }
}

impl<'de> DeserializeSeed<'de> for Limits<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Limits<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a property list value")
    }

    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<(), E> {
        self.charge(0)
    }

    fn visit_i64<E: de::Error>(self, _value: i64) -> Result<(), E> {
        self.charge(0)
    }

    fn visit_u64<E: de::Error>(self, _value: u64) -> Result<(), E> {
        self.charge(0)
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<(), E> {
        self.charge(0)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.charge(value.len())
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<(), E> {
        self.charge(value.len())
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
                Ok(Some(chunk)) if data.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
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
    fn rejects_values_that_expand_past_the_response_limit() {
        // A binary property list whose root dictionary holds `levels` nested arrays. Each array
        // lists the next level 8 times, so the reader expands it to 8^levels strings.
        let shared = |levels: u8| {
            let mut objects = vec![vec![0xd1, 1, 2], vec![0x51, b'a']];
            for level in 0..levels {
                let mut array = vec![0xa8];
                array.extend([level + 3; 8]);
                objects.push(array);
            }
            objects.push(vec![0x51, b'x']);
            let mut plist = b"bplist00".to_vec();
            let mut offsets = Vec::new();
            for object in &objects {
                offsets.push(u8::try_from(plist.len()).unwrap());
                plist.extend(object);
            }
            let table = u64::try_from(plist.len()).unwrap();
            plist.extend(offsets);
            plist.extend([0, 0, 0, 0, 0, 0, 1, 1]);
            plist.extend(u64::try_from(objects.len()).unwrap().to_be_bytes());
            plist.extend(0_u64.to_be_bytes());
            plist.extend(table.to_be_bytes());
            plist
        };
        assert_eq!(
            parse_response(&shared(2)).get("a").map(String::len),
            Some(64 * 3 - 2),
            "Expand a small shared array"
        );
        // 190 bytes that expand to 8^14 strings. Parsing did not finish before the limit.
        let plist = shared(14);
        assert_eq!(plist.len(), 190, "Fixture size");
        assert!(
            parse_response(&plist).is_empty(),
            "Reject a document that expands past the limit"
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
