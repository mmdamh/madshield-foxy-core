# Notice

This is the Foxy core of MadShield: the Go program MadShield runs for its "Firefox VPN" engine. It is MadShield's own
repository and is maintained here.

It was started from the source of an open-source, unofficial Firefox VPN client (GPL-3.0):
https://github.com/armanlife/firefox-vpn-client at commit `e9e6c49fbcb9ee219b74636239b9588582b38076` (version 1.0.8).
Its license is in `LICENSE`; the copyright and license notices of that source stay with the files that came from it.
This repository is licensed the same way, GNU General Public License v3.0.

What MadShield changed (all in this repository, as ordinary code, with tests):
- `core/cmd/madshield-fx/`: the entry point MadShield runs (loopback API that needs a token, SOCKS5 login, only-Mozilla
  settings, name allowlist, no account password on disk).
- `core/internal/fxa/madshield_*.go`, `core/internal/service/madshield_*.go`, `core/internal/proxy/madshield_*.go`,
  `core/internal/resolver/madshield.go`: browser sign-in tokens, the CAPTCHA renewal lifecycle, and hooks.
- the Go module is renamed to `github.com/mmdamh/madshield-foxy-core/core`.
- desktop-only parts (Flutter app, installers, Windows resources) are not included.

The program talks only to Mozilla (Firefox Accounts, the VPN service, the server list, the proxies) and to the DNS
servers MadShield gives it; see `core/cmd/madshield-fx/allow.go`.
