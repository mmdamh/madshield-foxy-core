# madshield-foxy-core

The Foxy core of [MadShield](https://github.com/mmdamh/MadShield): a static Go program (`core/cmd/madshield-fx`) that MadShield
runs as a child process for its "Firefox VPN" engine. MadShield's CI fetches this repository at the commit written in
MadShield's `native/fxvpn.pin` and builds it; there are no patches to apply.

- Build (what CI does): `cd core && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -buildid=" ./cmd/madshield-fx`
  after raising `klauspost/compress` to v1.20.2 and `quic-go` to v0.59.1 (CI checks both).
- Tests: `cd core && go test ./cmd/madshield-fx && go test -run TestMadShield ./internal/...`
- Changing it: commit here, then change the commit in MadShield's `native/fxvpn.pin`.
- Origin and license: see `NOTICE.md` and `LICENSE` (GPL-3.0).
