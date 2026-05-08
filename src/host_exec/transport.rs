//! Transport adapters for host-exec connections.
//!
//! Currently a placeholder — the per-platform listeners
//! (`linux_relay`, `macos_listener`) wrap their accepted file
//! descriptors in `std::net::UnixStream` / `std::net::TcpStream` /
//! file-fd directly, all of which already implement
//! `Read + Write + Send`.
