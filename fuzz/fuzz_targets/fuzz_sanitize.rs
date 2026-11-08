#![no_main]

use libfuzzer_sys::fuzz_target;
use usbguard_notifier_rs::sanitize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split input into max_len (first byte) and payload
    let max_len = (data[0] as usize).min(256);
    let payload = String::from_utf8_lossy(&data[1..]);

    let sanitized = sanitize(&payload, max_len, "fallback");

    // Invariants that must never be violated:
    if sanitized != "fallback" {
        // 1. Length bound
        assert!(
            sanitized.len() <= max_len.saturating_mul(6),
            "Output exceeded worst-case 6x entity bound: len={}, max_len={}",
            sanitized.len(),
            max_len
        );

        // 2. No unescaped '<' or '>'
        assert!(!sanitized.contains('<'), "Output contains unescaped '<'");
        assert!(!sanitized.contains('>'), "Output contains unescaped '>'");

        // 3. No raw control characters
        for c in sanitized.chars() {
            assert!(!c.is_control(), "Output contains control char {:?}", c);
        }

        // 4. No Trojan Source bidi override characters
        const BIDI_CHARS: &[char] = &[
            '\u{200E}', '\u{200F}',
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        for bidi in BIDI_CHARS {
            assert!(!sanitized.contains(*bidi), "Output contains bidi char {:?}", bidi);
        }
    }
});
