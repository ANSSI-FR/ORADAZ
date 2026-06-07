use base64::{Engine as _, engine::general_purpose::URL_SAFE};

/// Applies a specified transformation to a value, typically used for URL parameters.
///
/// Supported transformations:
/// - `None`: Returns the value as-is.
/// - `Base64`: URL-safe Base64 encoding of the value.
/// - `SplitBackslashFirstAndBase64`: Extracts the part before the first backslash and Base64 encodes it.
/// - `SplitBackslashSecondAndBase64`: Extracts the part after the first backslash (including the backslash) and Base64 encodes it.
/// - `AddBackslashAndBase64`: Prepends a backslash to the value and Base64 encodes it.
/// - `UrlEncode`: Percent-encodes the value as a single URL path segment (see
///   [`encode_path_segment`]). Opt-in protection for data-derived values that are
///   one path segment and may contain path-unsafe characters (`/ ? # %`, spaces) —
///   e.g. a management-group `name` or an ADHybridHealthService `serviceName`.
///   Values that are themselves a full resource path (e.g. an ARM `id` used as a
///   path prefix) must **not** declare this transform, so their `/` separators are
///   preserved.
pub fn apply_transform(value: &str, transform: Option<&str>) -> Option<String> {
    match transform {
        None => Some(value.to_string()),
        Some("Base64") => Some(URL_SAFE.encode(value.as_bytes())),
        Some("UrlEncode") => Some(encode_path_segment(value)),
        Some("SplitBackslashFirstAndBase64") => {
            Some(URL_SAFE.encode(value.split('\\').next().unwrap_or_default().as_bytes()))
        }
        Some("SplitBackslashSecondAndBase64") => Some(
            URL_SAFE
                .encode(format!("\\{}", value.split('\\').nth(1).unwrap_or_default()).as_bytes()),
        ),
        Some("AddBackslashAndBase64") => Some(URL_SAFE.encode(format!("\\{value}").as_bytes())),
        Some(_) => None,
    }
}

/// Percent-encodes a data-derived value for safe substitution into a URL **path
/// segment**.
///
/// The unreserved set (`A-Z a-z 0-9 - _ . ~`) plus `=` (Base64 padding) is left
/// byte-for-byte intact; every other byte — `/ ? # %`, spaces, control bytes,
/// non-ASCII — is percent-encoded. This keeps GUIDs and the URL-safe Base64 output
/// of [`apply_transform`] unchanged (they only ever use `A-Za-z0-9-_=`), while
/// preventing an identifier such as a management-group `name` or an
/// ADHybridHealthService `serviceName` that contains a path-unsafe character from
/// silently breaking the URL structure.
pub fn encode_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'=' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{apply_transform, encode_path_segment};

    #[test]
    fn urlencode_transform_encodes_segment_and_only_when_requested() {
        // `UrlEncode` percent-encodes a single path segment...
        assert_eq!(
            apply_transform("a/b c", Some("UrlEncode")).as_deref(),
            Some("a%2Fb%20c")
        );
        // ...while no transform leaves the value (e.g. a full resource path) raw.
        assert_eq!(
            apply_transform("/subscriptions/x/resourceGroups/y", None).as_deref(),
            Some("/subscriptions/x/resourceGroups/y")
        );
    }

    #[test]
    fn leaves_guids_and_base64_untouched() {
        // GUIDs and URL-safe Base64 (with `=` padding) must round-trip unchanged,
        // so existing relationship URLs are not altered.
        let guid = "b7d3a8b8-be41-4cb2-b73e-e34fd09c06a4";
        assert_eq!(encode_path_segment(guid), guid);
        let b64 = "dXNlckBleGFtcGxlLmNvbQ==";
        assert_eq!(encode_path_segment(b64), b64);
    }

    #[test]
    fn encodes_path_unsafe_characters() {
        assert_eq!(encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(encode_path_segment("a b"), "a%20b");
        assert_eq!(encode_path_segment("a?b#c"), "a%3Fb%23c");
        // No unsafe byte left unescaped.
        assert!(!encode_path_segment("x/y z?#%").contains(['/', ' ', '?', '#']));
    }
}
