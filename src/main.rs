//! usbguard-notifier-rs
//!
//! A lightweight, memory-safe, and interactive USBGuard desktop notification daemon written in Rust.
//! Bridges USBGuard D-Bus events with FreeDesktop/GNOME interactive notifications.

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use zbus::zvariant::Value;

// USBGuard Devices1 D-Bus Proxy
#[zbus::proxy(
    interface = "org.usbguard.Devices1",
    default_service = "org.usbguard1",
    default_path = "/org/usbguard1/Devices"
)]
trait Devices {
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

// FreeDesktop Notifications D-Bus Proxy
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    En,
    Pl,
}

struct I18n {
    title_blocked: &'static str,
    action_allow_once: &'static str,
    action_allow_perm: &'static str,
    action_block: &'static str,
    prompt_action: &'static str,
    hw_id: &'static str,
    port: &'static str,
    serial: &'static str,
    unknown: &'static str,
    allowed_once_title: &'static str,
    allowed_once_body: &'static str,
    allowed_perm_title: &'static str,
    allowed_perm_body: &'static str,
}

impl I18n {
    fn get(lang: Language) -> Self {
        match lang {
            Language::Pl => Self {
                title_blocked: "USBGuard: Zablokowano urządzenie USB",
                action_allow_once: "Zezwól (jednorazowo)",
                action_allow_perm: "Zezwól (na stałe)",
                action_block: "Zablokuj",
                prompt_action: "Wybierz akcję dla tego urządzenia:",
                hw_id: "ID sprzętu",
                port: "Port",
                serial: "Numer seryjny",
                unknown: "Nieznane",
                allowed_once_title: "USBGuard: Zezwolono",
                allowed_once_body: "Urządzenie zostało odblokowane jednorazowo.",
                allowed_perm_title: "USBGuard: Zezwolono na stałe",
                allowed_perm_body: "Reguła została trwale zapisana w konfiguracji USBGuard.",
            },
            Language::En => Self {
                title_blocked: "USBGuard: USB Device Blocked",
                action_allow_once: "Allow Once",
                action_allow_perm: "Allow Always",
                action_block: "Keep Blocked",
                prompt_action: "Choose an action for this device:",
                hw_id: "Hardware ID",
                port: "Port",
                serial: "Serial",
                unknown: "Unknown",
                allowed_once_title: "USBGuard: Device Allowed",
                allowed_once_body: "Device has been authorized for this session.",
                allowed_perm_title: "USBGuard: Device Allowed Permanently",
                allowed_perm_body: "Rule has been saved to USBGuard policy.",
            },
        }
    }
}

struct DeviceInfo {
    name: String,
    vid_pid: String,
    port: String,
    serial: String,
}

struct AppState {
    device_to_notif: HashMap<u32, u32>,
    notif_to_device: HashMap<u32, u32>,
    last_notified: HashMap<u32, Instant>,
}

impl AppState {
    fn new() -> Self {
        Self {
            device_to_notif: HashMap::new(),
            notif_to_device: HashMap::new(),
            last_notified: HashMap::new(),
        }
    }
}

/// Robust HTML/XML string sanitizer for desktop notifications.
/// Protects desktop notification servers (e.g. GNOME Shell Pango markup) against injection attacks.
fn sanitize_str(input: &str, max_len: usize, fallback: &str) -> String {
    let mut clean = String::with_capacity(input.len());
    for c in input.chars().take(max_len) {
        match c {
            '&' => clean.push_str("&amp;"),
            '<' => clean.push_str("&lt;"),
            '>' => clean.push_str("&gt;"),
            '"' => clean.push_str("&quot;"),
            '\'' => clean.push_str("&apos;"),
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

/// Extract and sanitize USB descriptor attributes from rules or D-Bus attribute map.
fn parse_device_info(device_rule: &str, attrs: &HashMap<String, String>, fallback: &str) -> DeviceInfo {
    let mut name = attrs.get("name").cloned().unwrap_or_default();
    let mut vid_pid = String::new();
    let mut port = attrs.get("via-port").cloned().unwrap_or_default();
    let mut serial = attrs.get("serial").cloned().unwrap_or_default();

    // Fallback extraction from rule string
    if name.is_empty() {
        if let Some(pos) = device_rule.find("name \"") {
            let start = pos + 6;
            if let Some(end) = device_rule[start..].find('"') {
                name = device_rule[start..start + end].to_string();
            }
        }
    }

    if let Some(pos) = device_rule.find("id ") {
        let start = pos + 3;
        let slice = &device_rule[start..];
        let end = slice.find(' ').unwrap_or(slice.len());
        vid_pid = slice[..end].to_string();
    }

    if port.is_empty() {
        if let Some(pos) = device_rule.find("via-port \"") {
            let start = pos + 10;
            if let Some(end) = device_rule[start..].find('"') {
                port = device_rule[start..start + end].to_string();
            }
        }
    }

    if serial.is_empty() {
        if let Some(pos) = device_rule.find("serial \"") {
            let start = pos + 8;
            if let Some(end) = device_rule[start..].find('"') {
                serial = device_rule[start..start + end].to_string();
            }
        }
    }

    DeviceInfo {
        name: sanitize_str(&name, 64, fallback),
        vid_pid: sanitize_str(&vid_pid, 16, fallback),
        port: sanitize_str(&port, 16, fallback),
        serial: sanitize_str(&serial, 32, fallback),
    }
}

struct Config {
    debug: bool,
    lang: Language,
}

fn print_help() {
    println!("usbguard-notifier-rs {}", env!("CARGO_PKG_VERSION"));
    println!("Interactive, memory-safe USBGuard desktop notification agent written in Rust.\n");
    println!("USAGE:");
    println!("    usbguard-notifier-rs [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    -d, --debug        Enable debug logging output to stderr");
    println!("    -l, --lang <LANG>  Force UI language ('en' or 'pl') [default: auto-detected from $LANG]");
    println!("    -h, --help         Print this help information");
    println!("    -V, --version      Print version information");
}

fn parse_args() -> Result<Config, ()> {
    let args: Vec<String> = env::args().collect();
    let mut debug = false;
    let mut lang = if env::var("LANG").unwrap_or_default().starts_with("pl") {
        Language::Pl
    } else {
        Language::En
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("usbguard-notifier-rs {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-d" | "--debug" => {
                debug = true;
            }
            "-l" | "--lang" => {
                if i + 1 < args.len() {
                    i += 1;
                    match args[i].to_lowercase().as_str() {
                        "pl" => lang = Language::Pl,
                        "en" => lang = Language::En,
                        other => {
                            eprintln!("[WARN] Unknown language '{}', falling back to English", other);
                            lang = Language::En;
                        }
                    }
                } else {
                    eprintln!("[ERROR] Option --lang requires an argument ('en' or 'pl')");
                    return Err(());
                }
            }
            other => {
                eprintln!("[ERROR] Unknown option '{}'", other);
                print_help();
                return Err(());
            }
        }
        i += 1;
    }

    Ok(Config { debug, lang })
}

async fn run(config: Config) -> zbus::Result<()> {
    let i18n = I18n::get(config.lang);

    if config.debug {
        eprintln!(
            "[DEBUG] Starting usbguard-notifier-rs v{} (language: {})",
            env!("CARGO_PKG_VERSION"),
            match config.lang {
                Language::Pl => "pl",
                Language::En => "en",
            }
        );
    }

    // Connect to system D-Bus (USBGuard) and session D-Bus (Notifications)
    let system_conn = zbus::connection::Builder::system()?.build().await?;
    let session_conn = zbus::connection::Builder::session()?.build().await?;

    let usbguard = DevicesProxy::new(&system_conn).await?;
    let notifications = NotificationsProxy::new(&session_conn).await?;

    let state = Arc::new(Mutex::new(AppState::new()));

    // Subscribe to signal streams
    let mut presence_stream = usbguard.receive_device_presence_changed().await?;
    let mut policy_stream = usbguard.receive_device_policy_changed().await?;
    let mut action_stream = notifications.receive_action_invoked().await?;
    let mut closed_stream = notifications.receive_notification_closed().await?;

    if config.debug {
        eprintln!("[DEBUG] Subscribed to USBGuard and Notification D-Bus signals. Ready.");
    }

    loop {
        futures_util::select! {
            // Signal 1: USBGuard device insertion / removal / presence change
            presence_res = presence_stream.next() => {
                if let Some(signal) = presence_res {
                    let args = match signal.args() {
                        Ok(a) => a,
                        Err(e) => {
                            if config.debug {
                                eprintln!("[DEBUG] Failed to deserialize DevicePresenceChanged: {e}");
                            }
                            continue;
                        }
                    };

                    let dev_id = args.id;
                    let event = args.event;   // 0 = Insert, 1 = Update, 2 = Remove
                    let target = args.target; // 0 = Allow, 1 = Block, 2 = Reject
                    let device_rule = &args.device_rule;
                    let attributes = &args.attributes;

                    // Physical device unplugged -> withdraw pending notification if active
                    if event == 2 {
                        let notif_to_close = {
                            let mut s = state.lock().unwrap();
                            if let Some(notif_id) = s.device_to_notif.remove(&dev_id) {
                                s.notif_to_device.remove(&notif_id);
                                Some(notif_id)
                            } else {
                                None
                            }
                        };
                        if let Some(nid) = notif_to_close {
                            let _ = notifications.close_notification(nid).await;
                            if config.debug {
                                eprintln!("[DEBUG] Device #{dev_id} removed; closed notification #{nid}");
                            }
                        }
                        continue;
                    }

                    // Blocked or Rejected device
                    if target != 0 {
                        // Anti-DoS rate-limiting debounce (2-second window per device ID)
                        {
                            let mut s = state.lock().unwrap();
                            let now = Instant::now();
                            if let Some(last) = s.last_notified.get(&dev_id) {
                                if now.duration_since(*last) < Duration::from_secs(2) {
                                    continue;
                                }
                            }
                            s.last_notified.insert(dev_id, now);
                        }

                        let info = parse_device_info(device_rule, attributes, i18n.unknown);

                        let summary = i18n.title_blocked;
                        let mut body = format!(
                            "<b>{}</b>\n{}: <code>{}</code>\n{}: <code>{}</code>",
                            info.name, i18n.hw_id, info.vid_pid, i18n.port, info.port
                        );
                        if !info.serial.is_empty() && info.serial != i18n.unknown {
                            body.push_str(&format!("\n{}: <code>{}</code>", i18n.serial, info.serial));
                        }
                        body.push_str(&format!("\n\n{}", i18n.prompt_action));

                        let actions = [
                            "allow_once", i18n.action_allow_once,
                            "allow_permanent", i18n.action_allow_perm,
                            "block", i18n.action_block,
                        ];

                        let mut hints = HashMap::new();
                        hints.insert("urgency", Value::U8(2)); // Critical urgency (does not auto-dismiss)
                        hints.insert("category", Value::Str("device.warning".into()));
                        hints.insert("desktop-entry", Value::Str("org.usbguard".into()));

                        let replaces_id = {
                            let s = state.lock().unwrap();
                            s.device_to_notif.get(&dev_id).copied().unwrap_or(0)
                        };

                        match notifications.notify(
                            "USBGuard",
                            replaces_id,
                            "security-high",
                            summary,
                            &body,
                            &actions,
                            &hints,
                            0, // 0 = Do not expire
                        ).await {
                            Ok(notif_id) => {
                                let mut s = state.lock().unwrap();
                                s.device_to_notif.insert(dev_id, notif_id);
                                s.notif_to_device.insert(notif_id, dev_id);
                                if config.debug {
                                    eprintln!("[DEBUG] Dispatched notification #{notif_id} for device #{dev_id} ({})", info.name);
                                }
                            }
                            Err(e) => {
                                eprintln!("[ERROR] Failed to send desktop notification: {e}");
                            }
                        }
                    }
                }
            }

            // Signal 2: Device policy changed (e.g. externally authorized)
            policy_res = policy_stream.next() => {
                if let Some(signal) = policy_res {
                    if let Ok(args) = signal.args() {
                        let dev_id = args.id;
                        let target_new = args.target_new;
                        // When allowed, close existing blocked notification
                        if target_new == 0 {
                            let notif_to_close = {
                                let mut s = state.lock().unwrap();
                                if let Some(notif_id) = s.device_to_notif.remove(&dev_id) {
                                    s.notif_to_device.remove(&notif_id);
                                    Some(notif_id)
                                } else {
                                    None
                                }
                            };
                            if let Some(nid) = notif_to_close {
                                let _ = notifications.close_notification(nid).await;
                            }
                        }
                    }
                }
            }

            // Signal 3: User clicked an action button on the desktop notification
            action_res = action_stream.next() => {
                if let Some(signal) = action_res {
                    if let Ok(args) = signal.args() {
                        let notif_id = args.id;
                        let action = args.action_key;

                        let dev_id_opt = {
                            let mut s = state.lock().unwrap();
                            let dev = s.notif_to_device.remove(&notif_id);
                            if let Some(dev_id) = dev {
                                s.device_to_notif.remove(&dev_id);
                            }
                            dev
                        };

                        if let Some(dev_id) = dev_id_opt {
                            match action.as_str() {
                                "allow_once" => {
                                    if config.debug {
                                        eprintln!("[DEBUG] Applying temporary policy (allow once) for device #{dev_id}");
                                    }
                                    match usbguard.apply_device_policy(dev_id, 0, false).await {
                                        Ok(_) => {
                                            let mut hints = HashMap::new();
                                            hints.insert("urgency", Value::U8(1));
                                            let _ = notifications.notify(
                                                "USBGuard",
                                                0,
                                                "security-low",
                                                i18n.allowed_once_title,
                                                i18n.allowed_once_body,
                                                &[],
                                                &hints,
                                                4000,
                                            ).await;
                                        }
                                        Err(e) => {
                                            eprintln!("[ERROR] Failed to apply allow_once policy: {e}");
                                        }
                                    }
                                }
                                "allow_permanent" => {
                                    if config.debug {
                                        eprintln!("[DEBUG] Applying permanent policy (allow always) for device #{dev_id}");
                                    }
                                    match usbguard.apply_device_policy(dev_id, 0, true).await {
                                        Ok(_) => {
                                            let mut hints = HashMap::new();
                                            hints.insert("urgency", Value::U8(1));
                                            let _ = notifications.notify(
                                                "USBGuard",
                                                0,
                                                "security-low",
                                                i18n.allowed_perm_title,
                                                i18n.allowed_perm_body,
                                                &[],
                                                &hints,
                                                4000,
                                            ).await;
                                        }
                                        Err(e) => {
                                            eprintln!("[ERROR] Failed to apply allow_permanent policy: {e}");
                                        }
                                    }
                                }
                                "block" => {
                                    if config.debug {
                                        eprintln!("[DEBUG] Keeping device #{dev_id} blocked");
                                    }
                                    let _ = usbguard.apply_device_policy(dev_id, 1, false).await;
                                }
                                _ => {
                                    if config.debug {
                                        eprintln!("[DEBUG] Ignored unknown action key: {action}");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Signal 4: Notification dismissed or closed
            closed_res = closed_stream.next() => {
                if let Some(signal) = closed_res {
                    if let Ok(args) = signal.args() {
                        let notif_id = args.id;
                        let mut s = state.lock().unwrap();
                        if let Some(dev_id) = s.notif_to_device.remove(&notif_id) {
                            s.device_to_notif.remove(&dev_id);
                        }
                    }
                }
            }
        }
    }
}

fn main() -> zbus::Result<()> {
    let config = match parse_args() {
        Ok(c) => c,
        Err(_) => std::process::exit(1),
    };

    async_io::block_on(run(config))
}
