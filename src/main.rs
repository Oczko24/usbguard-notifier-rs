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

use std::collections::HashMap;
use std::env;
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

// ---------------------------------------------------------------------------
// Core event loop session
// ---------------------------------------------------------------------------

/// Establishes D-Bus connections and runs the main event loop.
/// Returns `Ok(true)` if clean shutdown was signaled, or `Err` on connection failure / stream EOF.
async fn run_session(
    debug: bool,
    shutdown_rx: &Receiver<()>,
) -> Result<bool, Box<dyn std::error::Error>> {
    if debug {
        eprintln!("[DEBUG] Establishing D-Bus connections...");
    }

    let system_conn = zbus::connection::Builder::system()?.build().await?;
    let session_conn = zbus::connection::Builder::session()?.build().await?;

    let usbguard = DevicesProxy::new(&system_conn).await?;
    let notifications = NotificationsProxy::new(&session_conn).await?;

    let caps = ServerCaps::query(&notifications, debug).await;

    let mut presence_stream = usbguard.receive_device_presence_changed().await?;
    let mut policy_stream = usbguard.receive_device_policy_changed().await?;
    let mut action_stream = notifications.receive_action_invoked().await?;
    let mut closed_stream = notifications.receive_notification_closed().await?;

    let mut dev_to_notif: HashMap<u32, u32> = HashMap::new();
    let mut notif_to_dev: HashMap<u32, u32> = HashMap::new();
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
                for (_, nid) in dev_to_notif.drain() {
                    let _ = notifications.close_notification(nid).await;
                }
                notif_to_dev.clear();
                eprintln!("[INFO] Graceful shutdown complete. Closed active notifications.");
                return Ok(true);
            }

            // Signal: Device presence changed
            item = presence_stream.next() => {
                let signal = match item {
                    Some(s) => s,
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

                    // Anti-DoS: bound map size against unbounded growth
                    if last_notified.len() > 64 {
                        last_notified.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
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
                            let mut hints = HashMap::new();
                            hints.insert("urgency", Value::U8(2));
                            hints.insert("category", Value::Str("device.warning".into()));
                            let body = format!(
                                "Multiple USB devices blocked ({cascade_count}+).\nRun: usbguard list-devices"
                            );
                            let _ = notifications.notify(
                                "USBGuard", 0, "security-high",
                                "USB Device Cascade Detected",
                                &body, &[], &hints, 0,
                            ).await;
                        }
                        continue;
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

                    let raw_body = if caps.has_markup {
                        let mut b = format!(
                            "<b>{name}</b>\nHardware ID: <code>{vid_pid}</code>\nPort: <code>{port}</code>"
                        );
                        if !serial.is_empty() {
                            b.push_str(&format!("\nSerial: <code>{serial}</code>"));
                        }
                        b
                    } else {
                        let mut b = format!("{name}\nHardware ID: {vid_pid}\nPort: {port}");
                        if !serial.is_empty() {
                            b.push_str(&format!("\nSerial: {serial}"));
                        }
                        b
                    };

                    let (body, actions): (String, &[&str]) = if caps.has_actions {
                        let mut b = raw_body;
                        b.push_str("\n\nSelect an authorization policy:");
                        (b, &[
                            "allow_once", "Allow Once",
                            "allow_permanent", "Allow Always",
                            "block", "Keep Blocked",
                        ])
                    } else {
                        let mut b = raw_body;
                        b.push_str(&format!(
                            "\n\nTo authorize, run:\n  usbguard allow-device {dev_id}"
                        ));
                        (b, &[])
                    };

                    let final_body = if !caps.has_markup {
                        strip_markup(&body)
                    } else {
                        body
                    };

                    let mut hints = HashMap::new();
                    hints.insert("urgency", Value::U8(2));
                    hints.insert("category", Value::Str("device.warning".into()));
                    hints.insert("desktop-entry", Value::Str("org.usbguard".into()));

                    let replaces_id = dev_to_notif.get(&dev_id).copied().unwrap_or(0);

                    match notifications.notify(
                        "USBGuard", replaces_id, "security-high",
                        "USB Device Blocked", &final_body, actions, &hints, 0,
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
                    None => return Err("USBGuard policy signal stream ended".into()),
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
                    None => return Err("Notifications action signal stream ended".into()),
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
                    None => return Err("Notifications closed signal stream ended".into()),
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
        match run_session(debug, &shutdown_rx).await {
            Ok(true) => return Ok(()), // Clean shutdown requested
            Ok(false) => return Ok(()),
            Err(e) => {
                if shutdown_rx.is_closed() || !shutdown_rx.is_empty() {
                    return Ok(());
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
