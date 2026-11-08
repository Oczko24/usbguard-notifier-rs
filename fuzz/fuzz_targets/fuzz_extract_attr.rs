#![no_main]

use std::collections::HashMap;
use libfuzzer_sys::fuzz_target;
use usbguard_notifier_rs::extract_attr;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let input = String::from_utf8_lossy(data);
    let mut map = HashMap::new();

    // Populate fake map with some key variations
    map.insert("name".to_string(), "SanDisk Ultra".to_string());
    map.insert("id".to_string(), "0781:5583".to_string());

    // Keys commonly queried by the notifier daemon
    let test_keys = ["id", "name", "via-port", "serial", "hash", "target"];

    for key in &test_keys {
        // Must never panic on arbitrary malformed rule strings or UTF-8 slices
        let _ = extract_attr(&map, key, &input);
    }
});
