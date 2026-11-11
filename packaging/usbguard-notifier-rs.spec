%global crate_name usbguard-notifier-rs

Name:           %{crate_name}
Version:        0.2.2
Release:        1%{?dist}
Summary:        Minimal, hardened interactive USBGuard desktop notification daemon

License:        MIT OR Apache-2.0
URL:            https://github.com/Oczko24/%{crate_name}
Source0:        %{url}/archive/v%{version}/%{crate_name}-%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  rust >= 1.70.0
BuildRequires:  cargo >= 1.70.0
BuildRequires:  systemd-rpm-macros

Requires:       usbguard
Requires:       polkit
Recommends:     usbguard-dbus

%description
A lightweight, memory-safe, and interactive USBGuard desktop notification daemon
written in safe Rust. Bridges the system USBGuard daemon with FreeDesktop desktop
notifications to surface interactive prompts with one-click device authorization
(Allow Once, Allow Always, Keep Blocked).

Engineered with defense-in-depth against BadUSB descriptor spoofing, Pango markup
injection, bidirectional Unicode attacks, and notification flooding.

%prep
%autosetup -n %{crate_name}-%{version}

%build
export RUSTFLAGS="-D warnings"
cargo build --release

%install
install -Dpm 0755 target/release/%{crate_name} %{buildroot}%{_bindir}/%{crate_name}
install -Dpm 0644 systemd/%{crate_name}.service %{buildroot}%{_userunitdir}/%{crate_name}.service
install -Dpm 0644 polkit/70-usbguard-user.rules %{buildroot}%{_sysconfdir}/polkit-1/rules.d/70-usbguard-user.rules

%check
cargo test --release

%post
%systemd_user_post %{crate_name}.service

%preun
%systemd_user_preun %{crate_name}.service

%postun
%systemd_user_postun_with_restart %{crate_name}.service

%files
%license LICENSE
%doc README.md
%{_bindir}/%{crate_name}
%{_userunitdir}/%{crate_name}.service
%config(noreplace) %{_sysconfdir}/polkit-1/rules.d/70-usbguard-user.rules

%changelog
* Wed Nov 11 2026 Oczko24 <oczko24@users.noreply.github.com> - 0.2.2-1
- Security hardening and zero-unsafe codebase minimization (VICTORY CONFIRMED):
- Fix USBGuard EventType::Remove event handling to eliminate stale notification TOCTOU
- Scope polkit rules strictly to applyDevicePolicy and listDevices (wheel and sudo)
- BadUSB interface detection: alert user when blocked devices present HID or network interfaces
- Zero-allocation attribute parser with backslash-parity and token isolation
- Unicode line/paragraph separator sanitization (U+2028, U+2029) to prevent UI spoofing
- Determinist bounded FIFO prompt map (hard cap 32)
- Exponential reconnect backoff with 10s stability reset and RestartSteps=5 in systemd unit

* Wed Nov 11 2026 Oczko24 <oczko24@users.noreply.github.com> - 0.2.1-1
- Fix systemd user service binding: change WantedBy to graphical-session.target
- Resolves silent startup failure due to ConditionEnvironment=|WAYLAND_DISPLAY not met at early user session boot

* Sat Nov 08 2026 Oczko24 <oczko24@users.noreply.github.com> - 0.2.0-1
- Hardened v0.2.0 release: backoff reconnection, instant signal handling, proptest and packaging

* Sat Nov 08 2026 Oczko24 <oczko24@users.noreply.github.com> - 0.1.0-1
- Initial package release
- Safe Rust daemon with interactive USB device authorization notifications
- Systemd user service with comprehensive sandboxing
- Polkit rules for passwordless local wheel-group authorization
