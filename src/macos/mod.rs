//! macOS backend: Linux VM via Apple Virtualization.framework (arcbox-vz).
//!
//! Boots a Linux micro-VM running `tokimo-sandbox-init`, communicates over
//! virtio-vsock with the guest's init binary.

#[allow(dead_code)]
pub(crate) mod sandbox;
pub(crate) mod vm;
pub(crate) mod vsock_init_client;
