//! Property-based verification of sanitize() and extract_attr() parser invariants.
//! Proves that no attacker-controlled USB descriptor string can cause panics,
//! unbounded output growth, or markup injection.

#![forbid(unsafe_code)]

use proptest::prelude::*;
use std::collections::HashMap;
use usbguard_notifier_rs::{extract_attr, sanitize, strip_markup};

// Strategy for adversarial strings: mixes arbitrary UTF-8, Pango/HTML entities,
// Unicode bidi overrides, and ASCII control characters.
fn adversarial_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Arbitrary Unicode string
        any::<String>(),
        // HTML and Pango injection payloads
        Just("<script>alert('xss')</script>".into()),
        Just("<span foreground=\"red\">malicious</span>".into()),
        Just("<b>bold</b><i>italic</i><code>code</code>".into()),
        Just("&amp;&quot;&lt;&gt;&apos;".repeat(10)),
        // Trojan Source bidirectional override attacks
        Just("\u{202A}admin\u{202E}txt.exe\u{202C}".into()),
        Just("\u{200E}\u{200F}\u{2066}\u{2067}\u{2068}\u{2069}".repeat(50)),
        // ASCII control and ANSI terminal escape codes
        Just("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".repeat(10)),
        Just("\x1B[31;1mRedText\x1B[0m\r\n\t".into()),
        Just("\x7F\x1B]0;Injected Title\x07".into()),
        // Unicode line and paragraph separators
        Just("\u{2028}line\u{2029}break\u{2028}".into()),
        // Pathological edge cases
        Just("".into()),
        Just("   \t\r\n   ".into()),
        Just("a".repeat(10_000)),
        Just("&".repeat(2_000)),
        Just("<>".repeat(1_000)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_sanitize_never_panics(
        input in adversarial_string(),
        max_len in 0usize..1024,
        fallback in "[a-zA-Z0-9_-]{1,32}",
    ) {
        let _ = sanitize(&input, max_len, &fallback);
    }

    #[test]
    fn prop_sanitize_length_bounded(
        input in adversarial_string(),
        max_len in 0usize..512,
        fallback in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let result = sanitize(&input, max_len, &fallback);
        if result == fallback {
            prop_assert_eq!(result, fallback);
        } else {
            // Worst-case byte expansion is max_len * 6 bytes (e.g. &quot; or &apos;)
            prop_assert!(result.len() <= max_len.saturating_mul(6));
        }
    }

    #[test]
    fn prop_sanitize_no_raw_markup(
        input in adversarial_string(),
        max_len in 1usize..256,
        fallback in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let result = sanitize(&input, max_len, &fallback);
        if result != fallback {
            // Must contain no unescaped '<' or '>'
            prop_assert!(!result.contains('<'), "Result contains raw '<': {}", result);
            prop_assert!(!result.contains('>'), "Result contains raw '>': {}", result);

            // Any '&' in output must be part of a valid escaped entity: &amp;, &lt;, &gt;, &quot;, &apos;
            let mut slice = result.as_str();
            while let Some(idx) = slice.find('&') {
                let tail = &slice[idx..];
                let is_valid_entity = tail.starts_with("&amp;")
                    || tail.starts_with("&lt;")
                    || tail.starts_with("&gt;")
                    || tail.starts_with("&quot;")
                    || tail.starts_with("&apos;");
                prop_assert!(is_valid_entity, "Result contains unescaped '&': {}", result);
                slice = &slice[idx + 1..];
            }
        }
    }

    #[test]
    fn prop_sanitize_no_control_characters(
        input in adversarial_string(),
        max_len in 1usize..256,
        fallback in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let result = sanitize(&input, max_len, &fallback);
        // Result must never contain ASCII control chars (0x00..=0x1F or 0x7F)
        for c in result.chars() {
            prop_assert!(!c.is_control(), "Result contains control char {:?}: {}", c, result);
        }
    }

    #[test]
    fn prop_sanitize_no_bidi_overrides(
        input in adversarial_string(),
        max_len in 1usize..256,
        fallback in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let result = sanitize(&input, max_len, &fallback);
        const BIDI_CHARS: &[char] = &[
            '\u{200E}', '\u{200F}',
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        for bidi in BIDI_CHARS {
            prop_assert!(!result.contains(*bidi), "Result contains bidi char {:?}: {}", bidi, result);
        }
    }

    #[test]
    fn prop_sanitize_no_line_separators(
        input in adversarial_string(),
        max_len in 1usize..256,
        fallback in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let result = sanitize(&input, max_len, &fallback);
        prop_assert!(!result.contains('\u{2028}'), "Result contains U+2028: {}", result);
        prop_assert!(!result.contains('\u{2029}'), "Result contains U+2029: {}", result);
    }

    #[test]
    fn prop_extract_attr_never_panics(
        key in "[a-z-]{1,16}",
        rule in adversarial_string(),
    ) {
        let mut map = HashMap::new();
        map.insert("name".to_string(), "Device".to_string());
        map.insert("id".to_string(), "1234:5678".to_string());

        let _ = extract_attr(&map, &key, &rule);
    }

    #[test]
    fn prop_strip_markup_never_panics(
        input in adversarial_string(),
    ) {
        let stripped = strip_markup(&input);
        prop_assert!(!stripped.contains('<'));
        prop_assert!(!stripped.contains('>'));
    }

    #[test]
    fn prop_extract_attr_zero_allocation_subslice(
        key in "[a-z-]{1,16}",
        rule in adversarial_string(),
    ) {
        let empty_map = HashMap::new();
        let res = extract_attr(&empty_map, &key, &rule);
        if !res.is_empty() {
            let rule_start = rule.as_ptr() as usize;
            let rule_end = rule_start + rule.len();
            let res_start = res.as_ptr() as usize;
            let res_end = res_start + res.len();
            prop_assert!(res_start >= rule_start, "Subslice starts before rule buffer");
            prop_assert!(res_end <= rule_end, "Subslice ends after rule buffer");
        }
    }

    #[test]
    fn prop_extract_attr_token_isolation(
        key in prop_oneof![Just("serial"), Just("name"), Just("via-port")],
        spoofed in "[a-zA-Z0-9_-]{1,16}",
        genuine in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let empty_map = HashMap::new();
        let rule = format!(r#"block other "prefix {key} \"{spoofed}\" suffix" {key} "{genuine}""#);
        let extracted = extract_attr(&empty_map, key, &rule);
        prop_assert_eq!(extracted, genuine.as_str());
    }

    #[test]
    fn prop_extract_attr_id_isolation(
        spoofed_id in "[0-9a-f]{4}:[0-9a-f]{4}",
        genuine_id in "[0-9a-f]{4}:[0-9a-f]{4}",
    ) {
        let empty_map = HashMap::new();
        let rule = format!(r#"block name "Device id {spoofed_id}" id {genuine_id}"#);
        let extracted = extract_attr(&empty_map, "id", &rule);
        prop_assert_eq!(extracted, genuine_id.as_str());
    }

    #[test]
    fn prop_extract_attr_word_substring_isolation(
        word in prop_oneof![Just("Solid"), Just("liquid"), Just("rapid"), Just("Florida"), Just("uuid")],
        genuine_id in "[0-9a-f]{4}:[0-9a-f]{4}",
    ) {
        let empty_map = HashMap::new();
        let rule = format!(r#"block name "{word} State Drive" id {genuine_id}"#);
        let extracted = extract_attr(&empty_map, "id", &rule);
        prop_assert_eq!(extracted, genuine_id.as_str());
    }

    #[test]
    fn prop_sanitize_preserves_valid_unicode(
        input in "[a-zA-Z0-9\u{00C0}-\u{024F}\u{0400}-\u{04FF}\u{4E00}-\u{9FFF}]{1,32}",
    ) {
        let sanitized = sanitize(&input, 64, "fb");
        prop_assert_eq!(sanitized, input);
    }

    #[test]
    fn prop_extract_attr_escaped_quotes_isolation(
        key in prop_oneof![Just("serial"), Just("name"), Just("via-port")],
        val_with_escaped in r#"([a-zA-Z0-9 ]*\\"[a-zA-Z0-9 ]*){1,3}"#,
        genuine_id in "[0-9a-f]{4}:[0-9a-f]{4}",
    ) {
        let empty_map = HashMap::new();
        let rule = format!(r#"block other "{val_with_escaped}" id {genuine_id} {key} "target""#);
        let extracted_id = extract_attr(&empty_map, "id", &rule);
        prop_assert_eq!(extracted_id, genuine_id.as_str());
        let extracted_key = extract_attr(&empty_map, key, &rule);
        prop_assert_eq!(extracted_key, "target");
    }
}
