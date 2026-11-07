# usbguard-notifier-rs

A lightweight, memory-safe, and interactive desktop notification daemon for **USBGuard**, written in Rust.

---

## Overview

[USBGuard](https://usbguard.github.io/) is an essential Linux security software framework that protects against BadUSB attacks, rogue flash drives, and unauthorized hardware peripherals by enforcing an authorization whitelist for USB devices.

However, the default user experience on modern Linux desktop environments (like GNOME, KDE, and Sway/Wayland) suffers from major usability issues:
1. **Passive Notifications:** The official `usbguard-notifier` package only displays static, read-only desktop notifications (e.g. *"Device blocked"*). It provides no interactive buttons.
2. **Abandoned GUIs:** Legacy Qt-based applets (`usbguard-applet-qt`) were deprecated or removed from upstream package repositories years ago.
3. **Manual Friction:** Whenever you plug in an unwhitelisted device (a flash drive, game controller, audio interface, or diagnostic cable), you are forced to open a terminal, run `sudo usbguard list-devices`, identify the numeric ID, and execute `sudo usbguard allow-device <ID>`.

**`usbguard-notifier-rs` solves this friction cleanly and securely.** It monitors USBGuard events over the system D-Bus and instantly surfaces interactive desktop notifications with clickable action buttons:

* **[ Allow Once ]** / **[ Zezwól jednorazowo ]**: Authorizes the device temporarily for the active session. When unplugged, it returns to blocked.
* **[ Allow Always ]** / **[ Zezwól na stałe ]**: Permanently saves the device whitelist rule into `/etc/usbguard/rules.conf`. The device will be remembered across reboots.
* **[ Keep Blocked ]** / **[ Zablokuj ]**: Rejects the device and dismisses the notification.

---

## Key Features & Security Architecture

* **100% Safe Rust:** Written strictly in safe Rust (`#![forbid(unsafe_code)]`). Zero C FFI and no legacy C dependencies (`libdbus`, `libnotify`).
* **Input Sanitization against BadUSB Injection:** USB descriptors (Vendor ID, Product ID, Manufacturer, Product Name) are controlled by device firmware. Malicious hardware (e.g., Flipper Zero, Rubber Ducky) can send strings containing HTML/Pango markup or ANSI escape codes. All incoming descriptors are sanitized, escaped, and truncated before passing to the desktop notification server.
* **Anti-DoS / Debounce Protection:** Prevents notification queue flooding or desktop stutter caused by faulty cables or intentional high-frequency flapping/reconnecting attacks.
* **Dynamic Lifecycle Management:** If a blocked device is physically removed from the USB port before an action is chosen, the notification is automatically dismissed (`CloseNotification`).
* **Minimal Footprint:**
  * Binary size: ~1.9 MB (stripped, LTO enabled).
  * Runtime RAM usage: ~3 MB.
  * Idle CPU usage: 0%.
* **Automatic i18n:** Automatically adapts to your system language (`$LANG`), with English as default and built-in Polish translation (`--lang en` / `--lang pl`).
* **Least Privilege:** Runs entirely inside the unprivileged user session (`systemd --user`). Does not require root privileges or background daemons with elevated capabilities.

---

## Architecture Flow

```
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
| usbguard-notifier-rs (User Session Daemon)                  |
| -> Sanitizes USB descriptors, enforces debounce & rate-limit|
+-------------------------------------------------------------+
                              | (D-Bus Method: org.freedesktop.Notifications.Notify)
                              v
+-------------------------------------------------------------+
| Desktop Environment (GNOME Shell / Notification Daemon)     |
| Surfaces interactive notification with clickable buttons    |
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

Ensure `usbguard` and `usbguard-dbus` are installed and running on your system:

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

Ensure your user is in the `wheel` or `sudo` group so Polkit can delegate device policy permissions.

---

### 2. Build and Install from Source

```bash
git clone https://github.com/Oczko24/usbguard-notifier-rs.git
cd usbguard-notifier-rs
cargo build --release

# Install binary to user path
mkdir -p ~/.local/bin
cp target/release/usbguard-notifier-rs ~/.local/bin/
```

---

### 3. Setup Systemd User Service

1. Disable the passive default notifier (if installed):
```bash
systemctl --user stop usbguard-notifier 2>/dev/null || true
systemctl --user mask usbguard-notifier 2>/dev/null || true
```

2. Copy and enable the provided systemd service unit:
```bash
mkdir -p ~/.config/systemd/user
cp systemd/usbguard-notifier-rs.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now usbguard-notifier-rs.service
```

3. Check service status:
```bash
systemctl --user status usbguard-notifier-rs.service
```

---

### 4. Optional: Passwordless Approval via Polkit

By default, approving a USB device via D-Bus triggers a Polkit administrator authentication dialog (`auth_admin`).

If you prefer to allow active local users in the `wheel` group to authorize USB devices directly from notifications without entering your password every time, install the provided Polkit rule:

```bash
sudo cp polkit/70-usbguard-user.rules /etc/polkit-1/rules.d/
```

---

## CLI Options

```text
usbguard-notifier-rs 0.1.0
Interactive, memory-safe USBGuard desktop notification agent written in Rust.

USAGE:
    usbguard-notifier-rs [OPTIONS]

OPTIONS:
    -d, --debug        Enable debug logging output to stderr
    -l, --lang <LANG>  Force UI language ('en' or 'pl') [default: auto-detected from $LANG]
    -h, --help         Print this help information
    -V, --version      Print version information
```

---

## Security Hardening Details

The systemd service unit includes security restrictions:
* `NoNewPrivileges=yes`: Prevents gaining additional privileges through SUID executables.
* `ProtectSystem=strict`: The entire `/usr`, `/boot`, and `/etc` are mounted read-only for this process.
* `ProtectHome=read-only`: Protects your user home directory against unauthorized modifications.
* `PrivateTmp=yes`: Isolates the process `/tmp` directory.
* `RestrictSUIDSGID=yes`: Prevents creation of SUID/SGID files.
* `LockPersonality=yes`: Locks down execution domain changes.

---

## License

This project is licensed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
