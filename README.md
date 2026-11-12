# SFERA Server

Rust transport, Linux self-hosted installer and native mobile bindings for [SFERA clients](https://github.com/SFERA-TUN/sfera-client).

```sh
cargo build --locked --release --bin sfera-net
cargo test --locked
cargo test --locked --manifest-path bindings/mobile/Cargo.toml
python3 -m unittest discover -s tests -p 'test_selfhost.py'
```

Tags matching `server-v*` publish Linux x86_64 and aarch64 installation packages. The macOS client downloads the latest server release, verifies the SHA-256 digest supplied by GitHub and stages the package over SSH.

The self-hosted installer expects a dedicated Debian 12/13 or Ubuntu 24.04/26.04 VPS with public IPv4 and `/dev/net/tun`. It uses TCP 80 and 443, UDP 443 and loopback TCP 7443. Export a separate JSON profile for each device. Adding or revoking users restarts the server transport.

The mobile clients pin a server-core commit in `core.ref`. Publish compatible native binding changes before updating that pin.
