//! Single source of truth for the sandbox network topology.
//!
//! These constants describe the link between the host gateway (smoltcp
//! `Interface` in `crate::netstack`) and the guest's `tk0` TUN/TAP device.
//! Both sides MUST agree on every value — IP addresses, MAC addresses,
//! prefix lengths, and MTU. Consumers:
//!
//! - host-side: `crate::netstack`
//! - guest-side init pump: `src/bin/tokimo-sandbox-init/pump.rs`
//! - guest-side standalone tun pump: `src/bin/tokimo-tun-pump/main.rs`
//!
//! The module is unconditionally compiled (no `cfg` gates) so it can be
//! consumed from binaries that build on every platform; only the values
//! that are platform-specific (e.g. smoltcp wrappers in `netstack/mod.rs`)
//! live behind cfg.

#![allow(dead_code)]

// ─── IPv4 ────────────────────────────────────────────────────────────────────

/// Host gateway IPv4 address (what the guest sets as default route).
pub const HOST_IP4_OCTETS: [u8; 4] = [192, 168, 127, 1];

/// Guest IPv4 address — assigned to the guest TUN/TAP interface.
pub const GUEST_IP4_OCTETS: [u8; 4] = [192, 168, 127, 2];

/// Subnet prefix length (both ends share the /24).
pub const SUBNET4_PREFIX: u8 = 24;

// ─── IPv6 (ULA) ──────────────────────────────────────────────────────────────

/// Host gateway IPv6 address.
pub const HOST_IP6_SEGMENTS: [u16; 8] = [0xfd00, 0x007f, 0, 0, 0, 0, 0, 0x0001];

/// Guest IPv6 address.
pub const GUEST_IP6_SEGMENTS: [u16; 8] = [0xfd00, 0x007f, 0, 0, 0, 0, 0, 0x0002];

/// Subnet prefix length for IPv6.
pub const SUBNET6_PREFIX: u8 = 64;

// ─── Link layer ──────────────────────────────────────────────────────────────

/// Host gateway MAC — synthetic, picked outside the IANA OUI space.
pub const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Guest MAC — programmed into `tk0` by the guest pump.
pub const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Maximum transmission unit advertised on both ends, in bytes (payload
/// only; Ethernet header is +14).
pub const MTU: usize = 1400;

// ─── Vsock ───────────────────────────────────────────────────────────────────

/// Well-known vsock CID for the host (parent partition).
pub const VMADDR_CID_HOST: u32 = 2;

// ─── Ethernet framing on the guest↔host stream socket ───────────────────────

/// Frame size limit on the length-prefixed Ethernet stream between guest
/// `tk0` and host smoltcp `Interface`. Standard 16-bit length cap.
pub const ETHER_FRAME_MAX: usize = 65535;
