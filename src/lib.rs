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
/// - All ASCII control characters (0x00-0x1F, 0x7F) and Unicode line/paragraph separators (U+2028, U+2029) are replaced with spaces.
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
            // Replace control characters and Unicode line/paragraph breaks with space
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => clean.push(' '),
            c => clean.push(c),
        }
    }
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else if trimmed.len() == clean.len() {
        clean
    } else {
        trimmed.to_string()
    }
}

/// Counts the number of unescaped double quotes (`"`) in a slice.
/// A quote is considered escaped if preceded by an odd number of consecutive backslashes (`\`).
fn count_unescaped_quotes(slice: &str) -> usize {
    let bytes = slice.as_bytes();
    let mut count = 0;
    for i in 0..bytes.len() {
        if bytes[i] == b'"' {
            let backslashes = bytes[..i].iter().rev().take_while(|&&b| b == b'\\').count();
            if backslashes.is_multiple_of(2) {
                count += 1;
            }
        }
    }
    count
}

/// Finds the byte index of the first unescaped double quote (`"`) in a slice.
fn find_unescaped_quote(slice: &str) -> Option<usize> {
    let bytes = slice.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'"' {
            let backslashes = bytes[..i].iter().rev().take_while(|&&b| b == b'\\').count();
            if backslashes.is_multiple_of(2) {
                return Some(i);
            }
        }
    }
    None
}

/// Extracts a USB attribute from the D-Bus attribute map, falling back to parsing
/// the raw device rule string if the attribute map entry is missing.
pub fn extract_attr<'a>(attrs: &'a HashMap<String, String>, key: &str, rule: &'a str) -> &'a str {
    if key.is_empty() {
        return "";
    }
    if let Some(val) = attrs.get(key) {
        return val.as_str();
    }
    if key == "id" {
        for (i, _) in rule.match_indices("id ") {
            let before_ok = i == 0 || rule.as_bytes()[i - 1] == b' ';
            let outside_quotes = count_unescaped_quotes(&rule[..i]).is_multiple_of(2);
            if before_ok && outside_quotes {
                let rest = &rule[i + 3..];
                return rest.split_whitespace().next().unwrap_or("");
            }
        }
        return "";
    }
    for (i, _) in rule.match_indices(key) {
        let before_ok = i == 0 || rule.as_bytes()[i - 1] == b' ';
        let outside_quotes = count_unescaped_quotes(&rule[..i]).is_multiple_of(2);
        let after = &rule[i + key.len()..];
        if before_ok && outside_quotes && after.starts_with(" \"") {
            let content = &after[2..];
            if let Some(end) = find_unescaped_quote(content) {
                return &content[..end];
            }
        }
    }
    ""
}

/// Inspects USB device interface descriptors to alert on potential BadUSB hardware.
///
/// Interface descriptors are checked strictly within the interface list (`ifaces`),
/// falling back to the `with-interface` section of the rule only if `ifaces` is empty.
/// Ensures device names, serials, and IDs never trigger false positive warnings.
pub fn detect_badusb_interfaces(ifaces: &str, rule: &str) -> Option<&'static str> {
    let check = |code: &str| -> bool {
        if !ifaces.is_empty() {
            ifaces.contains(code)
        } else if let Some(pos) = rule.find("with-interface") {
            rule[pos..].contains(code)
        } else {
            false
        }
    };
    let has_hid = check("03:");
    let has_net = check("02:");
    match (has_hid, has_net) {
        (true, true) => Some("Warning: Device has HID (Keyboard) and Network interfaces"),
        (true, false) => Some("Warning: Device has HID (Keyboard/Mouse) interface"),
        (false, true) => Some("Warning: Device has Network Adapter interface"),
        (false, false) => None,
    }
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
    fn sanitize_replaces_unicode_line_separators() {
        assert_eq!(
            sanitize("Line1\u{2028}Line2\u{2029}Line3", 64, "fb"),
            "Line1 Line2 Line3"
        );
    }

    #[test]
    fn extract_attr_id_avoids_word_substrings() {
        let map = HashMap::new();
        let rule = r#"block name "Solid State Disk" id 1234:5678"#;
        assert_eq!(extract_attr(&map, "id", rule), "1234:5678");
    }

    #[test]
    fn extract_attr_preserves_empty_value_from_map() {
        let mut map = HashMap::new();
        map.insert("serial".to_string(), "".to_string());
        let rule = r#"block id 1234:5678 serial "SPOOFED""#;
        // Authoritative empty string in map must not fall back to rule string
        assert_eq!(extract_attr(&map, "serial", rule), "");
    }

    #[test]
    fn extract_attr_token_isolation_with_quoted_attribute() {
        let map = HashMap::new();
        let rule = r#"block name "Storage with serial \"SPOOF\" and id 0000:0000" id 1234:5678 serial "REAL_SERIAL""#;
        assert_eq!(extract_attr(&map, "id", rule), "1234:5678");
        assert_eq!(extract_attr(&map, "serial", rule), "REAL_SERIAL");
    }

    #[test]
    fn strip_markup_removes_tags() {
        assert_eq!(strip_markup("<b>bold</b> text"), "bold text");
        assert_eq!(strip_markup("<code>x</code>"), "x");
        assert_eq!(strip_markup("no tags"), "no tags");
    }

    #[test]
    fn extract_attr_empty_key_guard() {
        let map = HashMap::new();
        assert_eq!(
            extract_attr(&map, "", r#"block name "Device" id 1234:5678"#),
            ""
        );
    }

    #[test]
    fn extract_attr_escaped_quotes_parity_and_no_truncation() {
        let map = HashMap::new();
        let rule = r#"block name "Storage 2\" Drive" id 1234:5678 serial "XYZ""#;
        assert_eq!(extract_attr(&map, "name", rule), r#"Storage 2\" Drive"#);
        assert_eq!(extract_attr(&map, "id", rule), "1234:5678");
        assert_eq!(extract_attr(&map, "serial", rule), "XYZ");
    }

    #[test]
    fn extract_attr_spoofed_attribute_inside_escaped_quote_rejected() {
        let map = HashMap::new();
        let rule = r#"block name "Storage 2\" serial \"SPOOFED\" End" id 1234:5678 serial "REAL""#;
        assert_eq!(extract_attr(&map, "serial", rule), "REAL");
        assert_eq!(extract_attr(&map, "id", rule), "1234:5678");
    }

    #[test]
    fn extract_attr_escaped_backslash_handling() {
        let map = HashMap::new();
        // Two backslashes before quote = escaped backslash, quote is unescaped delimiter
        let rule = r#"block name "Path C:\\" id 1234:5678"#;
        assert_eq!(extract_attr(&map, "name", rule), r#"Path C:\\"#);
        assert_eq!(extract_attr(&map, "id", rule), "1234:5678");
    }

    #[test]
    fn detect_badusb_interfaces_no_false_positive_on_serial_or_name() {
        // Mass storage device with "03:" in serial and "02:" in name
        let rule = r#"block id 0781:5583 serial "03:12345" name "Cruzer Dial 02:Pro" with-interface { 08:06:50 }"#;
        assert_eq!(detect_badusb_interfaces("08:06:50", rule), None);
        assert_eq!(detect_badusb_interfaces("", rule), None);
    }

    #[test]
    fn detect_badusb_interfaces_detects_hid_and_network_combinations() {
        assert_eq!(
            detect_badusb_interfaces("03:01:01", ""),
            Some("Warning: Device has HID (Keyboard/Mouse) interface")
        );
        assert_eq!(
            detect_badusb_interfaces("02:06:00", ""),
            Some("Warning: Device has Network Adapter interface")
        );
        assert_eq!(
            detect_badusb_interfaces("03:00:00 02:00:00", ""),
            Some("Warning: Device has HID (Keyboard) and Network interfaces")
        );
    }

    #[test]
    fn detect_badusb_interfaces_fallback_to_rule_descriptor() {
        let hid_rule = r#"block id 1234:5678 serial "clean" with-interface { 03:01:01 }"#;
        assert_eq!(
            detect_badusb_interfaces("", hid_rule),
            Some("Warning: Device has HID (Keyboard/Mouse) interface")
        );
        let net_rule = r#"block id 1234:5678 serial "clean" with-interface { 02:01:01 }"#;
        assert_eq!(
            detect_badusb_interfaces("", net_rule),
            Some("Warning: Device has Network Adapter interface")
        );
    }
}
