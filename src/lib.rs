//! usbguard-notifier-rs library interface.
//!
//! Provides pure, hardened parsing and input sanitization routines for untrusted
//! USB descriptors and USBGuard D-Bus rule strings.
//! Used by the core daemon, integration test suites, and fuzzing targets.

#![forbid(unsafe_code)]

use std::collections::HashMap;

/// Sanitizes untrusted USB descriptor strings to prevent Pango/HTML markup injection,
/// ANSI terminal escapes, bidirectional text spoofing, and layout disruption.
///
/// Guarantees:
/// - Output character count is bounded by `max_len`.
/// - Output byte length is bounded by `max_len * 6` (worst-case entity expansion).
/// - No raw `<`, `>`, `&`, `"`, `'` characters remain.
/// - All ASCII control characters (0x00-0x1F, 0x7F) are replaced with spaces.
/// - All Unicode bidi override characters are stripped.
/// - If the sanitized result is empty (all whitespace/control), returns `fallback`.
pub fn sanitize(input: &str, max_len: usize, fallback: &str) -> String {
    let mut clean = String::with_capacity(input.len().min(max_len.saturating_mul(6)));
    for c in input.chars().take(max_len) {
        match c {
            '&' => clean.push_str("&amp;"),
            '<' => clean.push_str("&lt;"),
            '>' => clean.push_str("&gt;"),
            '"' => clean.push_str("&quot;"),
            '\'' => clean.push_str("&apos;"),
            // Strip bidirectional override characters (Trojan Source attacks)
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => (),
            // Replace control characters (including newlines and escapes) with space
            c if c.is_control() => clean.push(' '),
            c => clean.push(c),
        }
    }
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Extracts a USB attribute from the D-Bus attribute map, falling back to parsing
/// the raw device rule string if the attribute map entry is missing or empty.
pub fn extract_attr<'a>(attrs: &'a HashMap<String, String>, key: &str, rule: &'a str) -> &'a str {
    if let Some(val) = attrs.get(key) {
        if !val.is_empty() {
            return val.as_str();
        }
    }
    if key == "id" {
        if let Some(pos) = rule.find("id ") {
            return rule[pos + 3..].split_whitespace().next().unwrap_or("");
        }
    } else {
        let pattern = format!("{key} \"");
        if let Some(pos) = rule.find(&pattern) {
            let slice = &rule[pos + pattern.len()..];
            if let Some(end) = slice.find('"') {
                return &slice[..end];
            }
        }
    }
    ""
}

/// Strips Pango/HTML markup tags from a string for notification servers that do not
/// support the `body-markup` capability.
pub fn strip_markup(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut in_tag = false;
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => (),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_html_entities() {
        assert_eq!(
            sanitize("<script>alert(1)</script>", 64, "fb"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }

    #[test]
    fn sanitize_strips_bidi_overrides() {
        let input = "Normal\u{202A}Hidden\u{202C}Text";
        let result = sanitize(input, 64, "fb");
        assert!(!result.contains('\u{202A}'));
        assert!(!result.contains('\u{202C}'));
        assert_eq!(result, "NormalHiddenText");
    }

    #[test]
    fn sanitize_replaces_control_chars_with_space() {
        assert_eq!(sanitize("A\x00B\x1BC\x7FD", 64, "fb"), "A B C D");
    }

    #[test]
    fn sanitize_falls_back_on_empty() {
        assert_eq!(sanitize("", 64, "Unknown"), "Unknown");
        assert_eq!(sanitize("   ", 64, "Unknown"), "Unknown");
        assert_eq!(sanitize("\x00\x01\x02", 64, "Fallback"), "Fallback");
    }

    #[test]
    fn sanitize_respects_max_len() {
        let input = "A".repeat(200);
        let result = sanitize(&input, 10, "fb");
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn sanitize_max_len_zero_returns_fallback() {
        assert_eq!(sanitize("anything", 0, "Empty"), "Empty");
    }

    #[test]
    fn extract_attr_from_map() {
        let mut map = HashMap::new();
        map.insert("name".to_string(), "Kingston Flash".to_string());
        assert_eq!(extract_attr(&map, "name", ""), "Kingston Flash");
    }

    #[test]
    fn extract_attr_from_rule_string() {
        let map = HashMap::new();
        let rule = r#"allow id 1234:5678 serial "ABC" name "Test Device""#;
        assert_eq!(extract_attr(&map, "name", rule), "Test Device");
        assert_eq!(extract_attr(&map, "serial", rule), "ABC");
    }

    #[test]
    fn extract_attr_id_from_rule() {
        let map = HashMap::new();
        let rule = "block id 04f2:b604 serial \"\" name \"\" via-port \"1-5\"";
        assert_eq!(extract_attr(&map, "id", rule), "04f2:b604");
    }

    #[test]
    fn extract_attr_missing_key_returns_empty() {
        let map = HashMap::new();
        assert_eq!(extract_attr(&map, "nonexistent", "some rule"), "");
    }

    #[test]
    fn strip_markup_removes_tags() {
        assert_eq!(strip_markup("<b>bold</b> text"), "bold text");
        assert_eq!(strip_markup("<code>x</code>"), "x");
        assert_eq!(strip_markup("no tags"), "no tags");
    }
}
