# usbguard-notifier-rs

A minimal, memory-safe, hardened interactive desktop notification daemon for **USBGuard**, written in safe Rust.

> **Project Genesis & Engineering Standard:**  
> This project was developed through autonomous test-time compute scaling and iterative engineering refinement: zero runtime bloat, minimal source footprint, memory safety (`#![forbid(unsafe_code)]`), and defense-in-depth threat mitigation.

---

## Overview

[USBGuard](https://usbguard.github.io/) protects Linux systems against BadUSB attacks, rogue hardware, and unauthorized peripherals by enforcing a device authorization policy on the kernel USB stack.

However, default desktop notifications on modern Linux environments (GNOME Shell, KDE Plasma, Sway/Wayland) are passive:
1. **No Interactive Controls:** The standard `usbguard-notifier` package only displays read-only notifications ("Device blocked").
2. **Deprecated GUIs:** Legacy Qt applets (`usbguard-applet-qt`) are abandoned and removed from modern distribution repositories.
3. **Manual CLI Friction:** Authorizing a new flash drive, peripheral, or diagnostic cable requires opening a terminal and running manual `usbguard` CLI commands.

**`usbguard-notifier-rs` bridges this gap with an ultra-lightweight daemon.** It listens to USBGuard D-Bus events and immediately surfaces interactive notifications with one-click authorization:

* **Allow Once**: Temporarily authorizes the device for the current session. The device returns to blocked upon disconnection.
* **Allow Always**: Permanently appends an allow rule to `/etc/usbguard/rules.conf`. The device remains trusted across reboots.
* **Keep Blocked**: Rejects the device and dismisses the notification prompt.

---

## Security Architecture & Threat Model

USB descriptors (Vendor ID, Product ID, Manufacturer, Product Name, Serial) are unauthenticated inputs controlled entirely by the connected hardware microcontroller. A malicious USB device (e.g., Flipper Zero, USB Rubber Ducky, BadUSB) can craft adversarial payloads inside these fields.

`usbguard-notifier-rs` is engineered with defensive parsing, resilience, and system isolation:

* **100% Safe Rust:** Strictly enforced `#![forbid(unsafe_code)]`. Zero C FFI, no legacy C libraries (`libdbus`, `libnotify`).
* **Bidirectional Unicode Defense (Trojan Source):** Drops all Unicode bidi override characters (`U+202A` through `U+202E`, `U+2066` through `U+2069`, `U+200E`, `U+200F`) preventing visual spoofing and character order reversal attacks.
* **Pango & HTML Markup Sanitization:** Escapes all XML entities (`&`, `<`, `>`, `"`, `'`) and filters ANSI escape sequences and control characters before passing strings to the desktop notification server.
* **Length Caps & Input Truncation:** Enforces strict field boundaries (device names capped at 64 chars, IDs and ports at 16 chars, serials at 32 chars) preventing notification server memory exhaustion.
* **Anti-DoS & Multi-Device Cascade Protection:** Debounces rapid connect/disconnect cycles (2-second per-device window) to prevent desktop freezing during hardware fuzzing. Batches rapid multi-device cascades (more than 3 devices in 1 second) into summary alerts to prevent notification flooding.
* **Zero-Downtime Reconnection:** Wraps the D-Bus session in an internal exponential backoff loop (1s to 60s). If the D-Bus broker or `usbguard-daemon` restarts, the notifier recovers automatically without terminating.
* **Graceful Signal Handling:** Intercepts `SIGTERM`, `SIGINT`, and `SIGHUP` via safe signal streams. On termination, all open interactive notification prompts are cleanly dismissed via `CloseNotification` before process exit.
* **Server Capability Adaptation:** Queries `org.freedesktop.Notifications.GetCapabilities` at startup:
  - If `actions` is unsupported (minimal bars, headless tools), falls back to plain notifications containing CLI instructions (`usbguard allow-device <ID>`).
  - If `body-markup` is unsupported, strips all Pango tags (`<b>`, `<code>`) to preserve clean rendering.
* **Dynamic Lifecycle Tracking:** When a blocked device is physically removed before the user decides, its pending notification is withdrawn immediately via `CloseNotification`.
* **Micro Footprint:**
  - Binary size: ~1.2 MB (stripped, LTO enabled, size-optimized).
  - Runtime RAM usage: ~2.0 MB RSS.
  - Idle CPU usage: 0%.

---

## Architecture Flow

```text
+-------------------------------------------------------------+
| Physical Hardware (USB Port)                                |
+-------------------------------------------------------------+
                              | (USB Insert Event)
                              v
+-------------------------------------------------------------+
| Kernel + usbguard-daemon (Root System Service)              |
| -> Enforces default block policy on unrecognized hardware   |
+-------------------------------------------------------------+
                              | (D-Bus Signal: DevicePresenceChanged)
                              v
+-------------------------------------------------------------+
| usbguard-notifier-rs (Sandboxed User Session Daemon)         |
| -> Sanitizes descriptors, debounces, throttles cascades     |
| -> Introspects server capabilities (actions, body-markup)   |
+-------------------------------------------------------------+
                              | (D-Bus Method: org.freedesktop.Notifications.Notify)
                              v
+-------------------------------------------------------------+
| Desktop Environment (GNOME Shell / Notification Server)     |
| Surfaces interactive prompt with action buttons:            |
| [ Allow Once ]   [ Allow Always ]   [ Keep Blocked ]        |
+-------------------------------------------------------------+
                              | (User clicks Action)
                              v
+-------------------------------------------------------------+
| usbguard-notifier-rs                                        |
| -> Calls org.usbguard.Devices1.applyDevicePolicy(id, ...)   |
+-------------------------------------------------------------+
```

---

## Installation

### 1. Prerequisites

Ensure `usbguard` and `usbguard-dbus` are installed and running:

**Fedora / RHEL:**
```bash
sudo dnf install usbguard usbguard-dbus
sudo systemctl enable --now usbguard usbguard-dbus
```

**Arch Linux:**
```bash
sudo pacman -S usbguard
sudo systemctl enable --now usbguard
```

**Ubuntu / Debian:**
```bash
sudo apt install usbguard
sudo systemctl enable --now usbguard
```

Ensure your user belongs to the `wheel` or `sudo` group so Polkit can delegate authorization.

---

### 2. Build and Install from Source

```bash
git clone https://github.com/Oczko24/usbguard-notifier-rs.git
cd usbguard-notifier-rs
cargo build --release

# Install binary to user local path
mkdir -p ~/.local/bin
cp target/release/usbguard-notifier-rs ~/.local/bin/
chmod +x ~/.local/bin/usbguard-notifier-rs
```

---

### 3. Setup Systemd User Service

1. Mask the passive default notifier (if installed):
```bash
systemctl --user stop usbguard-notifier 2>/dev/null || true
systemctl --user mask usbguard-notifier 2>/dev/null || true
```

2. Install and enable the hardened user service:
```bash
mkdir -p ~/.config/systemd/user
cp systemd/usbguard-notifier-rs.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now usbguard-notifier-rs.service
```

3. Verify service status:
```bash
systemctl --user status usbguard-notifier-rs.service
```

---

### 4. Polkit Configuration

Authorizing devices via D-Bus triggers a Polkit prompt. To allow local users in the `wheel` group to authorize devices directly from notification buttons without typing passwords every time, install the included rule:

```bash
sudo cp polkit/70-usbguard-user.rules /etc/polkit-1/rules.d/
```

**Security Constraints in Polkit Rule:**
- `subject.active`: Only foreground VT/seat sessions (prevents background process abuse).
- `subject.local`: Only physically local sessions (prevents remote SSH session hijacking).
- `subject.isInGroup("wheel")`: Restricted strictly to administrative users.
- Explicitly scoped action IDs: `applyDevicePolicy`, `listDevices`, `appendRule`, `removeRule`.

---

## Verification & Fuzzing

The crate includes property-based tests using `proptest` and `cargo-fuzz` targets:

```bash
# Run unit and property tests (3,500 fuzzed property test cases)
cargo test --all-targets

# Run sanitization property suite specifically
cargo test --test sanitize_properties

# Run cargo fuzz (requires nightly toolchain and cargo-fuzz)
cargo +nightly fuzz run fuzz_sanitize
cargo +nightly fuzz run fuzz_extract_attr
```

---

## CLI Options

```text
usbguard-notifier-rs 0.2.1
Minimal, hardened interactive USBGuard notification daemon.

Usage: usbguard-notifier-rs [OPTIONS]

Options:
  -d, --debug    Enable debug logging to stderr
  -h, --help     Print help
  -V, --version  Print version
```

---

## Systemd Hardening Profile

The provided unit runs with sandboxing restrictions verified by `systemd-analyze`:

* `NoNewPrivileges=yes`: Prevents gaining extra privileges via SUID binaries.
* `ProtectSystem=strict`: Mounts `/usr`, `/boot`, and `/etc` strictly read-only.
* `ProtectHome=read-only`: Disallows modifying files in the home directory.
* `PrivateTmp=yes`: Provides an isolated `/tmp` namespace.
* `RestrictSUIDSGID=yes`: Prevents creating setuid/setgid files.
* `LockPersonality=yes`: Prevents ABI personality shifts.
* `MemoryDenyWriteExecute=yes`: Disallows creating writable and executable memory mappings.
* `RestrictNamespaces=yes`: Disallows creating arbitrary kernel namespaces.
* `SystemCallArchitectures=native`: Restricts syscalls to native architecture.
* `SystemCallFilter=@system-service @signal`: Restricts allowable kernel syscalls to bare essentials.
* `SystemCallFilter=~@privileged @resources @mount @clock @cpu-emulation @debug @module @raw-io @reboot @swap @obsolete`: Blacklists dangerous kernel syscall categories.
* `RestrictAddressFamilies=AF_UNIX`: Blocks all IP networking (`AF_INET`, `AF_INET6`, `AF_NETLINK`, `AF_PACKET`); only allows local UNIX domain sockets.
* `IPAddressDeny=any`: BPF firewall blocks all IP traffic at kernel socket layer.
* `CapabilityBoundingSet=` & `AmbientCapabilities=`: Drops all Linux kernel capabilities.
* `UMask=0077`: Restricts file creation permissions.

---

## Packaging

Pre-configured distribution packaging manifests are provided in `packaging/`:
* **Fedora / RHEL:** `packaging/usbguard-notifier-rs.spec`
* **Arch Linux:** `packaging/PKGBUILD`

---

## License

This project is licensed under the terms of the MIT License or Apache-2.0. See [LICENSE](LICENSE) for details.
