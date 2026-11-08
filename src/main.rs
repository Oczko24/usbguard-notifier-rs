//! usbguard-notifier-rs
//!
//! A minimal, memory-safe, hardened interactive USBGuard notification daemon.
//! Vibecoded with high-effort engineering rigor.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use zbus::zvariant::Value;

#[zbus::proxy(
    interface = "org.usbguard.Devices1",
    default_service = "org.usbguard1",
    default_path = "/org/usbguard1/Devices"
)]
trait Devices {
    #[zbus(name = "applyDevicePolicy")]
    fn apply_device_policy(&self, id: u32, target: u32, permanent: bool) -> zbus::Result<u32>;

    #[zbus(signal)]
    fn device_presence_changed(
        &self,
        id: u32,
        event: u32,
        target: u32,
        device_rule: String,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    fn device_policy_changed(
        &self,
        id: u32,
        target_old: u32,
        target_new: u32,
        device_rule: String,
        rule_id: u32,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: &HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// Sanitizes untrusted USB descriptor strings to prevent Pango/HTML markup injection,
/// ANSI terminal escapes, bidirectional text spoofing, and layout disruption.
fn sanitize(input: &str, max_len: usize, fallback: &str) -> String {
    let mut clean = String::with_capacity(input.len().min(max_len * 6));
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

/// Extracts a USB attribute from the D-Bus map, falling back to parsing the raw device rule string.
fn extract_attr<'a>(attrs: &'a HashMap<String, String>, key: &str, rule: &'a str) -> &'a str {
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

async fn run(debug: bool) -> zbus::Result<()> {
    if debug {
        eprintln!("[DEBUG] Starting usbguard-notifier-rs v{}", env!("CARGO_PKG_VERSION"));
    }

    let system_conn = zbus::connection::Builder::system()?.build().await?;
    let session_conn = zbus::connection::Builder::session()?.build().await?;

    let usbguard = DevicesProxy::new(&system_conn).await?;
    let notifications = NotificationsProxy::new(&session_conn).await?;

    let mut presence_stream = usbguard.receive_device_presence_changed().await?;
    let mut policy_stream = usbguard.receive_device_policy_changed().await?;
    let mut action_stream = notifications.receive_action_invoked().await?;
    let mut closed_stream = notifications.receive_notification_closed().await?;

    let mut dev_to_notif: HashMap<u32, u32> = HashMap::new();
    let mut notif_to_dev: HashMap<u32, u32> = HashMap::new();
    let mut last_notified: HashMap<u32, Instant> = HashMap::new();

    if debug {
        eprintln!("[DEBUG] Subscribed to USBGuard & Notification D-Bus signals. Active.");
    }

    loop {
        futures_util::select! {
            // Signal: Device presence changed
            item = presence_stream.next() => {
                let signal = match item {
                    Some(s) => s,
                    None => return Err(zbus::Error::InputOutput(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "USBGuard presence signal stream ended",
                    ).into())),
                };

                let args = match signal.args() {
                    Ok(a) => a,
                    Err(e) => {
                        if debug { eprintln!("[DEBUG] Malformed DevicePresenceChanged signal: {e}"); }
                        continue;
                    }
                };

                let dev_id = args.id;
                let event = args.event;   // 0 = Insert, 1 = Update, 2 = Remove
                let target = args.target; // 0 = Allow, 1 = Block, 2 = Reject

                // Device physically removed -> close active notification
                if event == 2 {
                    if let Some(nid) = dev_to_notif.remove(&dev_id) {
                        notif_to_dev.remove(&nid);
                        let _ = notifications.close_notification(nid).await;
                        if debug { eprintln!("[DEBUG] Device #{dev_id} removed; closed notification #{nid}"); }
                    }
                    continue;
                }

                // Device is blocked or rejected -> display interactive prompt
                if target != 0 {
                    let now = Instant::now();
                    // Bound map size against unbounded growth / DoS
                    if last_notified.len() > 64 {
                        last_notified.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
                    }
                    if let Some(prev) = last_notified.get(&dev_id) {
                        if now.duration_since(*prev) < Duration::from_secs(2) {
                            continue;
                        }
                    }
                    last_notified.insert(dev_id, now);

                    let name = sanitize(extract_attr(&args.attributes, "name", &args.device_rule), 64, "Unknown Device");
                    let vid_pid = sanitize(extract_attr(&args.attributes, "id", &args.device_rule), 16, "unknown");
                    let port = sanitize(extract_attr(&args.attributes, "via-port", &args.device_rule), 16, "unknown");
                    let serial = sanitize(extract_attr(&args.attributes, "serial", &args.device_rule), 32, "");

                    let mut body = format!("<b>{name}</b>\nHardware ID: <code>{vid_pid}</code>\nPort: <code>{port}</code>");
                    if !serial.is_empty() {
                        body.push_str(&format!("\nSerial: <code>{serial}</code>"));
                    }
                    body.push_str("\n\nSelect an authorization policy:");

                    let actions = [
                        "allow_once", "Allow Once",
                        "allow_permanent", "Allow Always",
                        "block", "Keep Blocked",
                    ];

                    let mut hints = HashMap::new();
                    hints.insert("urgency", Value::U8(2)); // Critical: persists until user interaction
                    hints.insert("category", Value::Str("device.warning".into()));
                    hints.insert("desktop-entry", Value::Str("org.usbguard".into()));

                    let replaces_id = dev_to_notif.get(&dev_id).copied().unwrap_or(0);

                    match notifications.notify(
                        "USBGuard",
                        replaces_id,
                        "security-high",
                        "USB Device Blocked",
                        &body,
                        &actions,
                        &hints,
                        0,
                    ).await {
                        Ok(nid) => {
                            dev_to_notif.insert(dev_id, nid);
                            notif_to_dev.insert(nid, dev_id);
                            if debug {
                                eprintln!("[DEBUG] Dispatched notification #{nid} for device #{dev_id} ({name})");
                            }
                        }
                        Err(e) => eprintln!("[ERROR] Failed to send desktop notification: {e}"),
                    }
                }
            }

            // Signal: Device policy changed (e.g., allowed externally via CLI)
            item = policy_stream.next() => {
                let signal = match item {
                    Some(s) => s,
                    None => return Err(zbus::Error::InputOutput(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "USBGuard policy signal stream ended",
                    ).into())),
                };

                if let Ok(args) = signal.args() {
                    if args.target_new == 0 {
                        if let Some(nid) = dev_to_notif.remove(&args.id) {
                            notif_to_dev.remove(&nid);
                            let _ = notifications.close_notification(nid).await;
                        }
                    }
                }
            }

            // Signal: User clicked an action on notification
            item = action_stream.next() => {
                let signal = match item {
                    Some(s) => s,
                    None => return Err(zbus::Error::InputOutput(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "Notifications action signal stream ended",
                    ).into())),
                };

                if let Ok(args) = signal.args() {
                    let nid = args.id;
                    if let Some(dev_id) = notif_to_dev.remove(&nid) {
                        dev_to_notif.remove(&dev_id);

                        match args.action_key.as_str() {
                            "allow_once" => {
                                if debug { eprintln!("[DEBUG] Applying temporary authorization for #{dev_id}"); }
                                match usbguard.apply_device_policy(dev_id, 0, false).await {
                                    Ok(_) => {
                                        let mut hints = HashMap::new();
                                        hints.insert("urgency", Value::U8(1));
                                        let _ = notifications.notify(
                                            "USBGuard", 0, "security-low",
                                            "USB Device Authorized",
                                            "Device authorized temporarily for this session.",
                                            &[], &hints, 3000,
                                        ).await;
                                    }
                                    Err(e) => eprintln!("[ERROR] Failed to apply allow_once policy: {e}"),
                                }
                            }
                            "allow_permanent" => {
                                if debug { eprintln!("[DEBUG] Applying permanent authorization for #{dev_id}"); }
                                match usbguard.apply_device_policy(dev_id, 0, true).await {
                                    Ok(_) => {
                                        let mut hints = HashMap::new();
                                        hints.insert("urgency", Value::U8(1));
                                        let _ = notifications.notify(
                                            "USBGuard", 0, "security-low",
                                            "USB Device Whitelisted",
                                            "Permanent whitelist rule saved to USBGuard policy.",
                                            &[], &hints, 3000,
                                        ).await;
                                    }
                                    Err(e) => eprintln!("[ERROR] Failed to apply allow_permanent policy: {e}"),
                                }
                            }
                            "block" => {
                                if debug { eprintln!("[DEBUG] Keeping device #{dev_id} blocked"); }
                                let _ = usbguard.apply_device_policy(dev_id, 1, false).await;
                            }
                            _ => (),
                        }
                    }
                }
            }

            // Signal: Notification closed / dismissed
            item = closed_stream.next() => {
                let signal = match item {
                    Some(s) => s,
                    None => return Err(zbus::Error::InputOutput(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "Notifications closed signal stream ended",
                    ).into())),
                };

                if let Ok(args) = signal.args() {
                    if let Some(dev_id) = notif_to_dev.remove(&args.id) {
                        dev_to_notif.remove(&dev_id);
                    }
                }
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut debug = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "-d" | "--debug" => debug = true,
            "-h" | "--help" => {
                println!("usbguard-notifier-rs {}", env!("CARGO_PKG_VERSION"));
                println!("Minimal, hardened interactive USBGuard notification daemon.\n");
                println!("Usage: usbguard-notifier-rs [OPTIONS]\n");
                println!("Options:");
                println!("  -d, --debug    Enable debug logging to stderr");
                println!("  -h, --help     Print help");
                println!("  -V, --version  Print version");
                return Ok(());
            }
            "-v" | "-V" | "--version" => {
                println!("usbguard-notifier-rs {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                eprintln!("[ERROR] Unknown argument '{other}'. Use --help for usage.");
                std::process::exit(1);
            }
        }
    }

    async_io::block_on(run(debug))?;
    Ok(())
}
