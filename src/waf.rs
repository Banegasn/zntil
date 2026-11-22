//! Bounded inspection using the vendored upstream libinjection tokenizer.
use percent_encoding::percent_decode_str;
use std::ffi::{c_char, c_int};

unsafe extern "C" {
    fn libinjection_sqli(s: *const c_char, len: usize, fingerprint: *mut c_char) -> c_int;
    fn libinjection_xss(s: *const c_char, len: usize) -> c_int;
}

#[derive(Clone, Copy, Default)]
pub enum BodyKind {
    Json,
    Form,
    Text,
    #[default]
    Opaque,
}
impl BodyKind {
    pub fn from_type(value: &str) -> Self {
        let mime = value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if mime == "application/json" || mime.ends_with("+json") {
            Self::Json
        } else if mime == "application/x-www-form-urlencoded" {
            Self::Form
        } else if mime.starts_with("text/") {
            Self::Text
        } else {
            Self::Opaque
        }
    }
}

pub fn injection(value: &[u8]) -> bool {
    let mut fingerprint = [0 as c_char; 8];
    // SAFETY: immutable input is valid for len bytes, and fingerprint is an eight-byte output.
    // Upstream API is length-delimited, accepts embedded nulls, and uses only per-call state.
    unsafe {
        libinjection_sqli(value.as_ptr().cast(), value.len(), fingerprint.as_mut_ptr()) != 0
            || libinjection_xss(value.as_ptr().cast(), value.len()) != 0
    }
}

pub fn parameters(raw: &str) -> bool {
    raw.split('&').flat_map(|p| p.splitn(2, '=')).any(|value| {
        let value = value.replace('+', " ");
        let first: Vec<u8> = percent_decode_str(&value).collect();
        if injection(&first) {
            return true;
        }
        let Ok(text) = std::str::from_utf8(&first) else {
            return false;
        };
        let second: Vec<u8> = percent_decode_str(text).collect();
        second != first && injection(&second)
    })
}

pub fn body(kind: BodyKind, raw: &[u8]) -> bool {
    match kind {
        BodyKind::Json => match serde_json::from_slice::<serde_json::Value>(raw) {
            Ok(v) => json_injection(&v),
            Err(_) => true,
        },
        BodyKind::Form => std::str::from_utf8(raw).map_or(true, parameters),
        BodyKind::Text => injection(raw),
        BodyKind::Opaque => false,
    }
}

fn json_injection(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => injection(s.as_bytes()),
        serde_json::Value::Array(a) => a.iter().any(json_injection),
        serde_json::Value::Object(o) => o
            .iter()
            .any(|(k, v)| injection(k.as_bytes()) || json_injection(v)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_encoded_sqli_and_xss() {
        assert!(parameters("q=%27%20OR%20%271%27%3D%271%27%20--"));
        assert!(parameters(
            "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
        ));
        assert!(!parameters("q=hello+world&page=2"));
    }
    #[test]
    fn inspects_json_strings_and_form() {
        assert!(body(
            BodyKind::Json,
            br#"{"nested":["<script>alert(1)</script>"]}"#
        ));
        assert!(!body(
            BodyKind::Json,
            br#"{"message":"Hello Nico","page":2}"#
        ));
        assert!(body(BodyKind::Form, b"q=%3Cscript%3Ealert(1)%3C/script%3E"));
    }
}
