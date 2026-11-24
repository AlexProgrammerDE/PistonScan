use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use plist::{Value, stream::Event};

use crate::snapshot::ServiceInfo;

/// Device information dictionaries nest a few levels deep. `display` recurses once per level.
const MAX_DEPTH: usize = 16;
/// `fetch` reads at most this many bytes of a response body.
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MIN_RFC3339_UNIX_SECONDS: u64 = 62_167_219_200;
const MAX_RFC3339_UNIX_SECONDS: u64 = 253_402_300_799;

#[must_use]
pub fn should_query(services: &[ServiceInfo]) -> bool {
    services
        .iter()
        .any(|service| service.port == 7000 && service.protocol.eq_ignore_ascii_case("tcp"))
}

#[must_use]
pub fn parse_response(data: &[u8]) -> BTreeMap<String, String> {
    // Check the limits first, so a hostile response cannot build a value that overflows the stack.
    if !is_bounded_plist(data) {
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

/// Checks the decoded event stream before building a `Value` tree.
///
/// A binary property list can reference one object many times, and the reader copies the object
/// for each reference. A few hundred bytes can therefore expand to more values than fit in memory.
fn is_bounded_plist(data: &[u8]) -> bool {
    let mut depth = 0_usize;
    let mut budget = MAX_RESPONSE_BYTES;
    for event in plist::stream::Reader::new(Cursor::new(data)) {
        let Ok(event) = event else {
            return false;
        };
        let charge = match &event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                if depth == MAX_DEPTH {
                    return false;
                }
                depth += 1;
                1
            }
            Event::EndCollection => {
                let Some(parent_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = parent_depth;
                0
            }
            Event::Data(value) => value.len().saturating_add(1),
            Event::String(value) => value.len().saturating_add(1),
            Event::Date(value) => {
                let timestamp: SystemTime = (*value).into();
                let in_range = match timestamp.duration_since(UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs() <= MAX_RFC3339_UNIX_SECONDS,
                    Err(error) => error.duration() <= Duration::from_secs(MIN_RFC3339_UNIX_SECONDS),
                };
                if !in_range {
                    return false;
                }
                1
            }
            Event::Boolean(_) | Event::Integer(_) | Event::Real(_) | Event::Uid(_) | _ => 1,
        };
        let Some(remaining) = budget.checked_sub(charge) else {
            return false;
        };
        budget = remaining;
    }
    depth == 0
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
        .timeout(Duration::from_millis(1500))
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
    use super::{MAX_DEPTH, MIN_RFC3339_UNIX_SECONDS, display, parse_response, should_query};
    use crate::snapshot::ServiceInfo;
    use plist::{Dictionary, Value};
    use std::time::{Duration, UNIX_EPOCH};

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
    fn rejects_unformattable_binary_dates() {
        let sample = include_bytes!("../fuzz/seeds/airplay_plist/date-overflow.bplist");
        assert!(
            parse_response(sample).is_empty(),
            "Reject a binary plist with a date outside the RFC 3339 formatter range"
        );
    }

    #[test]
    fn rejects_fractional_date_before_rfc3339_lower_bound() {
        let timestamp = UNIX_EPOCH
            .checked_sub(Duration::from_secs(MIN_RFC3339_UNIX_SECONDS))
            .and_then(|value| value.checked_sub(Duration::from_millis(1)))
            .expect("The RFC 3339 lower-bound fixture fits in SystemTime");
        let value = Value::Dictionary(Dictionary::from_iter([(
            "date",
            Value::Date(timestamp.into()),
        )]));
        let mut sample = Vec::new();
        value
            .to_writer_binary(&mut sample)
            .expect("Serialize the out-of-range date fixture");

        assert!(
            parse_response(&sample).is_empty(),
            "Reject a fractional date before the RFC 3339 lower bound"
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
