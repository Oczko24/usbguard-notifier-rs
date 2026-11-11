//! usbguard-notifier-rs
//!
//! A minimal, memory-safe, hardened interactive USBGuard desktop notification daemon.
//! Bridges `org.usbguard1` D-Bus signals with FreeDesktop desktop notifications
//! to provide one-click USB device authorization (Allow Once / Allow Always / Keep Blocked).
//!
//! Engineered with defense-in-depth against BadUSB descriptor spoofing, Pango markup
//! injection, bidirectional Unicode attacks, notification flooding, and D-Bus broker
//! disconnections with automatic exponential backoff reconnection.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]

use std::collections::{HashMap, VecDeque};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_channel::Receiver;
use futures_util::{FutureExt, StreamExt};
use usbguard_notifier_rs::{extract_attr, sanitize, strip_markup};
use zbus::zvariant::Value;

// ---------------------------------------------------------------------------
// D-Bus proxy definitions
// ---------------------------------------------------------------------------

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

    /// Queries the notification server for supported capabilities.
    fn get_capabilities(&self) -> zbus::Result<Vec<String>>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Desktop notification server capabilities
// ---------------------------------------------------------------------------

/// Notification server capability flags, queried once at session startup.
struct ServerCaps {
    has_actions: bool,
    has_markup: bool,
}

impl ServerCaps {
    async fn query(proxy: &NotificationsProxy<'_>, debug: bool) -> Self {
        let caps = proxy.get_capabilities().await.unwrap_or_default();
        let has_actions = caps.iter().any(|c| c == "actions");
        let has_markup = caps.iter().any(|c| c == "body-markup");
        if debug {
            eprintln!(
                "[DEBUG] Notification server capabilities: actions={has_actions}, markup={has_markup} (raw: {caps:?})"
            );
        }
        Self {
            has_actions,
            has_markup,
        }
    }
}

/// Dispatches a desktop notification with standardized hints.
async fn send_notification(
    proxy: &NotificationsProxy<'_>,
    replaces_id: u32,
    icon: &str,
    summary: &str,
    body: &str,
    actions: &[&str],
    urgency: u8,
    timeout: i32,
    desktop_entry: bool,
) -> zbus::Result<u32> {
    let mut hints = HashMap::new();
    hints.insert("urgency", Value::U8(urgency));
    if urgency > 1 {
        hints.insert("category", Value::Str("device.warning".into()));
    }
    if desktop_entry {
        hints.insert("desktop-entry", Value::Str("org.usbguard".into()));
    }
    proxy
        .notify(
            "USBGuard",
            replaces_id,
            icon,
            summary,
            body,
            actions,
            &hints,
            timeout,
        )
        .await
}

/// Inspects USB device interface descriptors to alert on potential BadUSB hardware.
fn detect_badusb_interfaces(ifaces: &str, rule: &str) -> Option<&'static str> {
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

/// Bounded prompt map maintaining exact FIFO eviction order (capacity: 32).
#[derive(Default)]
struct PromptMap {
    map: HashMap<u32, u32>,
    order: VecDeque<u32>,
}

impl PromptMap {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, dev_id: &u32) -> Option<u32> {
        self.map.get(dev_id).copied()
    }

    /// Inserts a notification ID for a device ID.
    /// If the map is at capacity (32) and `dev_id` is new, evicts the oldest entry (FIFO)
    /// and returns its notification ID so it can be dismissed.
    fn insert(&mut self, dev_id: u32, nid: u32) -> Option<u32> {
        let mut evicted_nid = None;
        if self.map.len() >= 32 && !self.map.contains_key(&dev_id) {
            while let Some(old_dev) = self.order.pop_front() {
                if let Some(old_nid) = self.map.remove(&old_dev) {
                    evicted_nid = Some(old_nid);
                    break;
                }
            }
        }
        if !self.map.contains_key(&dev_id) {
            self.order.push_back(dev_id);
        }
        self.map.insert(dev_id, nid);
        evicted_nid
    }

    /// Removes a device ID and its notification ID from tracking.
    fn remove(&mut self, dev_id: &u32) -> Option<u32> {
        let nid = self.map.remove(dev_id);
        if nid.is_some() {
            self.order.retain(|id| id != dev_id);
        }
        nid
    }

    /// Removes by notification ID, if present.
    fn remove_by_nid(&mut self, nid: u32) -> Option<u32> {
        let dev_id = self.find_dev_by_nid(nid)?;
        self.remove(&dev_id);
        Some(dev_id)
    }

    /// Finds the device ID associated with an active notification ID.
    fn find_dev_by_nid(&self, nid: u32) -> Option<u32> {
        self.map.iter().find(|(_, &n)| n == nid).map(|(&d, _)| d)
    }

    /// Drains all active prompts (e.g. on shutdown).
    fn drain(&mut self) -> std::collections::hash_map::Drain<'_, u32, u32> {
        self.order.clear();
        self.map.drain()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

// ---------------------------------------------------------------------------
// Core event loop session
// ---------------------------------------------------------------------------

/// Establishes D-Bus connections and runs the main event loop.
/// Returns `Ok(())` on clean shutdown, or `Err` on connection failure / stream EOF.
async fn run_session(
    debug: bool,
    shutdown_rx: &Receiver<()>,
    signal_received: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error>> {
    if debug {
        eprintln!("[DEBUG] Establishing D-Bus connections...");
    }

    let system_conn = zbus::connection::Builder::system()?.build().await?;
    let session_conn = zbus::connection::Builder::session()?.build().await?;

    let usbguard = DevicesProxy::new(&system_conn).await?;
    let notifications = NotificationsProxy::new(&session_conn).await?;

    let mut caps = ServerCaps::query(&notifications, debug).await;

    let mut presence_stream = usbguard.receive_device_presence_changed().await?;
    let mut policy_stream = usbguard.receive_device_policy_changed().await?;
    let mut action_stream = notifications.receive_action_invoked().await?;
    let mut closed_stream = notifications.receive_notification_closed().await?;

    let mut prompts = PromptMap::new();
    let mut last_notified: HashMap<u32, Instant> = HashMap::new();

    // Cascade detection: track rapid multi-device arrivals within a 1-second window
    let mut cascade_start: Option<Instant> = None;
    let mut cascade_count: u32 = 0;
    const CASCADE_WINDOW: Duration = Duration::from_secs(1);
    const CASCADE_THRESHOLD: u32 = 3;

    if debug {
        eprintln!("[DEBUG] Subscribed to USBGuard & Notification D-Bus signals. Active.");
    }

    loop {
        futures_util::select! {
            // Signal: External shutdown (SIGTERM / SIGINT) -> wake immediately and dismiss active prompts
            _ = shutdown_rx.recv().fuse() => {
                for (_, nid) in prompts.drain() {
                    let _ = notifications.close_notification(nid).await;
                }
                eprintln!("[INFO] Graceful shutdown complete. Closed active notifications.");
                return Ok(());
            }

            // Signal: Device presence changed
            item = presence_stream.next() => {
                let signal = match item {
                    Some(s) => {
                        signal_received.store(true, Ordering::Relaxed);
                        s
                    }
                    None => return Err("USBGuard presence signal stream ended".into()),
                };

                let args = match signal.args() {
                    Ok(a) => a,
                    Err(e) => {
                        if debug { eprintln!("[DEBUG] Malformed DevicePresenceChanged signal: {e}"); }
                        continue;
                    }
                };

                let dev_id = args.id;
                let event = args.event;   // USBGuard EventType: 0=Present, 1=Insert, 2=Update, 3=Remove
                let target = args.target; // 0 = Allow, 1 = Block, 2 = Reject
                const EVENT_REMOVE: u32 = 3;

                // Device physically removed -> close active notification and clean tracking
                if event == EVENT_REMOVE {
                    if let Some(nid) = prompts.remove(&dev_id) {
                        let _ = notifications.close_notification(nid).await;
                        if debug { eprintln!("[DEBUG] Device #{dev_id} removed; closed notification #{nid}"); }
                    }
                    last_notified.remove(&dev_id);
                    continue;
                }

                // Device is blocked or rejected -> display interactive prompt
                if target != 0 {
                    let now = Instant::now();

                    // Anti-DoS: bound map size against unbounded growth during hardware fuzzing
                    if last_notified.len() > 64 {
                        last_notified.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
                        if last_notified.len() > 64 {
                            last_notified.clear();
                        }
                    }

                    // Per-device debounce: 2-second window
                    if let Some(prev) = last_notified.get(&dev_id) {
                        if now.duration_since(*prev) < Duration::from_secs(2) {
                            continue;
                        }
                    }
                    last_notified.insert(dev_id, now);

                    // Cascade detection: batch rapid multi-device arrivals
                    match cascade_start {
                        Some(start) if now.duration_since(start) < CASCADE_WINDOW => {
                            cascade_count += 1;
                        }
                        _ => {
                            cascade_start = Some(now);
                            cascade_count = 1;
                        }
                    }

                    if cascade_count > CASCADE_THRESHOLD {
                        if cascade_count == CASCADE_THRESHOLD + 1 {
                            let body = format!(
                                "Multiple USB devices blocked ({cascade_count}+).\nRun: usbguard list-devices"
                            );
                            let _ = send_notification(
                                &notifications, 0, "security-high",
                                "USB Device Cascade Detected",
                                &body, &[], 2, 0, false,
                            ).await;
                        }
                        continue;
                    }

                    // Dynamic capability refresh: re-query if daemon initially lacked actions
                    if !caps.has_actions {
                        caps = ServerCaps::query(&notifications, debug).await;
                    }

                    let name = sanitize(
                        extract_attr(&args.attributes, "name", &args.device_rule), 64, "Unknown Device"
                    );
                    let vid_pid = sanitize(
                        extract_attr(&args.attributes, "id", &args.device_rule), 16, "unknown"
                    );
                    let port = sanitize(
                        extract_attr(&args.attributes, "via-port", &args.device_rule), 16, "unknown"
                    );
                    let serial = sanitize(
                        extract_attr(&args.attributes, "serial", &args.device_rule), 32, ""
                    );

                    // Inspect interface classes to alert on potential BadUSB (HID keyboard / Network)
                    let ifaces = extract_attr(&args.attributes, "with-interface", &args.device_rule);
                    let type_warning = detect_badusb_interfaces(ifaces, &args.device_rule);

                    let mut body = format!(
                        "<b>{name}</b>\nHardware ID: <code>{vid_pid}</code>\nPort: <code>{port}</code>"
                    );
                    if !serial.is_empty() {
                        body.push_str(&format!("\nSerial: <code>{serial}</code>"));
                    }
                    if let Some(warn) = type_warning {
                        body.push_str(&format!("\n<b>{warn}</b>"));
                    }

                    let actions: &[&str] = if caps.has_actions {
                        body.push_str("\n\nSelect an authorization policy:");
                        &[
                            "allow_once", "Allow Once",
                            "allow_permanent", "Allow Always",
                            "block", "Keep Blocked",
                        ]
                    } else {
                        body.push_str(&format!(
                            "\n\nTo authorize, run:\n  usbguard allow-device {dev_id}"
                        ));
                        &[]
                    };

                    let final_body = if caps.has_markup { body } else { strip_markup(&body) };
                    let replaces_id = prompts.get(&dev_id).unwrap_or(0);

                    match send_notification(
                        &notifications, replaces_id, "security-high",
                        "USB Device Blocked", &final_body, actions, 2, 0, true,
                    ).await {
                        Ok(nid) => {
                            if let Some(old_nid) = prompts.insert(dev_id, nid) {
                                let _ = notifications.close_notification(old_nid).await;
                            }
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
                    Some(s) => {
                        signal_received.store(true, Ordering::Relaxed);
                        s
                    }
                    None => return Err("USBGuard policy signal stream ended".into()),
                };

                if let Ok(args) = signal.args() {
                    if args.target_new == 0 {
                        if let Some(nid) = prompts.remove(&args.id) {
                            let _ = notifications.close_notification(nid).await;
                        }
                    }
                }
            }

            // Signal: User clicked an action on notification
            item = action_stream.next() => {
                let signal = match item {
                    Some(s) => {
                        signal_received.store(true, Ordering::Relaxed);
                        s
                    }
                    None => return Err("Notifications action signal stream ended".into()),
                };

                if let Ok(args) = signal.args() {
                    let nid = args.id;
                    let dev_id = prompts.find_dev_by_nid(nid);
                    if let Some(dev_id) = dev_id {
                        prompts.remove(&dev_id);

                        match args.action_key.as_str() {
                            "allow_once" | "allow_permanent" => {
                                let permanent = args.action_key == "allow_permanent";
                                let (summary, body) = if permanent {
                                    ("USB Device Whitelisted", "Permanent whitelist rule saved to USBGuard policy.")
                                } else {
                                    ("USB Device Authorized", "Device authorized temporarily for this session.")
                                };
                                if debug {
                                    eprintln!(
                                        "[DEBUG] Applying {} authorization for #{dev_id}",
                                        if permanent { "permanent" } else { "temporary" }
                                    );
                                }
                                match usbguard.apply_device_policy(dev_id, 0, permanent).await {
                                    Ok(_) => {
                                        let _ = send_notification(
                                            &notifications, 0, "security-low",
                                             summary, body, &[], 1, 3000, false,
                                        ).await;
                                    }
                                    Err(e) => eprintln!("[ERROR] Failed to apply policy: {e}"),
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
                    Some(s) => {
                        signal_received.store(true, Ordering::Relaxed);
                        s
                    }
                    None => return Err("Notifications closed signal stream ended".into()),
                };

                if let Ok(args) = signal.args() {
                    prompts.remove_by_nid(args.id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reconnection loop with exponential backoff & signal handling
// ---------------------------------------------------------------------------

/// Outer daemon loop: runs `run_session` inside an exponential backoff reconnection
/// strategy. If the D-Bus broker or USBGuard daemon restarts, the notifier recovers
/// automatically without process termination. Only explicit SIGTERM/SIGINT causes exit.
async fn daemon_loop(debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = async_channel::bounded::<()>(1);

    // Register UNIX signal handlers via signal-hook's safe self-pipe pattern.
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ])?;

    std::thread::Builder::new()
        .name("signal-handler".to_string())
        .spawn(move || {
            for sig in signals.forever() {
                match sig {
                    signal_hook::consts::SIGTERM | signal_hook::consts::SIGINT => {
                        eprintln!("[INFO] Received termination signal ({sig}), shutting down...");
                        let _ = shutdown_tx.try_send(());
                        return;
                    }
                    signal_hook::consts::SIGHUP => {
                        eprintln!("[INFO] Received SIGHUP (reload request acknowledged, no-op).");
                    }
                    _ => (),
                }
            }
        })?;

    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    eprintln!(
        "[INFO] usbguard-notifier-rs v{} starting.",
        env!("CARGO_PKG_VERSION")
    );

    loop {
        let session_start = Instant::now();
        let signal_received = AtomicBool::new(false);
        match run_session(debug, &shutdown_rx, &signal_received).await {
            Ok(()) => return Ok(()), // Clean shutdown requested
            Err(e) => {
                if shutdown_rx.is_closed() || !shutdown_rx.is_empty() {
                    return Ok(());
                }

                // Reset exponential backoff if session ran stably (>10s) or received valid signal
                if session_start.elapsed() > Duration::from_secs(10)
                    || signal_received.load(Ordering::Relaxed)
                {
                    backoff = Duration::from_secs(1);
                }

                eprintln!(
                    "[WARN] Session terminated: {e}. Reconnecting in {} seconds...",
                    backoff.as_secs()
                );

                // Await timer or immediate shutdown signal during backoff
                futures_util::select! {
                    _ = FutureExt::fuse(async_io::Timer::after(backoff)) => {},
                    _ = shutdown_rx.recv().fuse() => {
                        eprintln!("[INFO] Shutdown received during backoff. Exiting cleanly.");
                        return Ok(());
                    }
                }

                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

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

    async_io::block_on(daemon_loop(debug))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_badusb_scoping_no_false_positive_on_serial_and_name() {
        let rule = r#"block id 0781:5583 serial "03:12345" name "Cruzer Dial 02:Pro" with-interface { 08:06:50 }"#;
        // With explicit non-HID interface list
        assert_eq!(detect_badusb_interfaces("08:06:50", rule), None);
        // With empty ifaces, falling back to with-interface in rule
        assert_eq!(detect_badusb_interfaces("", rule), None);
    }

    #[test]
    fn test_badusb_scoping_detects_genuine_interfaces() {
        let hid_rule = r#"block id 1234:5678 serial "00:00" with-interface { 03:01:01 }"#;
        assert_eq!(
            detect_badusb_interfaces("", hid_rule),
            Some("Warning: Device has HID (Keyboard/Mouse) interface")
        );
        let net_rule = r#"block id 1234:5678 serial "00:00" with-interface { 02:00:00 }"#;
        assert_eq!(
            detect_badusb_interfaces("", net_rule),
            Some("Warning: Device has Network Adapter interface")
        );
        let both_rule = r#"block id 1234:5678 with-interface { 03:01:01 02:00:00 }"#;
        assert_eq!(
            detect_badusb_interfaces("", both_rule),
            Some("Warning: Device has HID (Keyboard) and Network interfaces")
        );
    }

    #[test]
    fn test_prompt_map_fifo_eviction_order() {
        let mut prompts = PromptMap::new();

        // Fill capacity (32 entries: 1..=32)
        for i in 1..=32 {
            let evicted = prompts.insert(i, i * 10);
            assert_eq!(evicted, None);
        }
        assert_eq!(prompts.len(), 32);

        // Insert entry 33: should evict entry 1 (oldest)
        let evicted = prompts.insert(33, 330);
        assert_eq!(evicted, Some(10)); // nid of dev_id 1
        assert_eq!(prompts.get(&1), None);
        assert_eq!(prompts.get(&33), Some(330));
        assert_eq!(prompts.len(), 32);

        // Insert entry 34: should evict entry 2
        let evicted = prompts.insert(34, 340);
        assert_eq!(evicted, Some(20));
        assert_eq!(prompts.get(&2), None);
        assert_eq!(prompts.len(), 32);
    }

    #[test]
    fn test_prompt_map_flood_strict_fifo() {
        let mut prompts = PromptMap::new();

        // Flood with 1000 items
        for i in 1..=1000 {
            prompts.insert(i, i * 100);
        }
        assert_eq!(prompts.len(), 32);

        // In strict FIFO, only entries 969..=1000 should survive
        for i in 1..=968 {
            assert_eq!(
                prompts.get(&i),
                None,
                "Entry {} should have been evicted",
                i
            );
        }
        for i in 969..=1000 {
            assert_eq!(prompts.get(&i), Some(i * 100), "Entry {} should survive", i);
        }
    }

    #[test]
    fn test_prompt_map_removal_maintains_fifo_integrity() {
        let mut prompts = PromptMap::new();

        for i in 1..=5 {
            prompts.insert(i, i * 10);
        }

        // Remove dev_id 3 in the middle
        assert_eq!(prompts.remove(&3), Some(30));
        assert_eq!(prompts.len(), 4);

        // Remove by nid for dev_id 2
        assert_eq!(prompts.remove_by_nid(20), Some(2));
        assert_eq!(prompts.len(), 3);

        // Remaining devices in order should be 1, 4, 5
        assert_eq!(prompts.order, VecDeque::from(vec![1, 4, 5]));
    }
}
