# ch backend (Cloud Hypervisor)

Linux has two `SandboxBackend` implementations sharing the same
`tokimo-sandbox-init` guest binary:

| Backend | Isolation | Module |
|---|---|---|
| `bwrap` | Linux namespaces only | `src/linux/bwrap/` |
| `ch`    | KVM micro-VM (Cloud Hypervisor + virtiofsd) | `src/linux/ch/` |

The ch backend is the strongest Linux isolation tier and mirrors the macOS
backend in structure — VZ is swapped for Cloud Hypervisor and the in-process
`SingleDirectoryShare` is swapped for an out-of-process `virtiofsd`.

## Architecture

```
Sandbox client (library, in-process)
        │
        ├─ spawn cloud-hypervisor (--vsock cid=3,socket=<UDS>)
        │       │
        │       ├─ kernel: .vm/base/vmlinuz (same Debian bzImage as mac/win)
        │       ├─ initrd: .vm/base/initrd.img (same as mac/win)
        │       ├─ virtiofs share: tag="work" → <vm_dir>/rootfs/
        │       ├─ cmdline: tokimo.session=1 tokimo.init_port=<P>
        │       │           tokimo.guest_listens=0 …  (mac-style)
        │       └─ net: tk0 (smoltcp via tokimo-tun-pump in-guest)
        │
        ├─ spawn virtiofsd: socket=<vm_dir>/virtiofsd.sock, --shared-dir <rootfs>
        │   tag matches the kernel cmdline's virtiofs root (handled by init.sh).
        │
        └─ FuseHost (in-process) accept()s on <UDS>_<fuse_port>
           hybrid-vsock sidecar. The guest's tokimo-sandbox-fuse children
           connect *out* through vsock to register their mount.

Guest side (unchanged):
        packaging/vm-base/init.sh (PID 1 in initrd)
          → detects virtiofs tag "work" → chroots
          → parses tokimo.init_port / tokimo.guest_listens / netstack_port
          → exec tokimo-sandbox-init  (same PID 1 binary mac/win use)
                ↳ vsock CONNECT  to host port P → InitClient protocol
```

The control plane (`InitClient<VsockSend>`) is identical to the macOS path
(see `src/init_client/vsock.rs`).

## Hybrid-vsock direction

Cloud Hypervisor's `--vsock cid=N,socket=<UDS>` exposes a UNIX domain socket
that the host uses for *both* directions:

- **Host → guest** (we use this for `init`): open `<UDS>`, write
  `CONNECT <port>\n`, read `OK <port>\n`, then the stream is the vsock pipe
  to the guest port. Implemented in `src/linux/ch/vmm.rs` as
  `connect_init_via_hybrid_vsock`.
- **Guest → host** (we use this for FUSE bridge children): the host listens
  on `<UDS>_<port>` (firecracker convention; ch v51 supports it). Each
  guest-side `tokimo-sandbox-fuse` child connects out, the host accepts,
  and `FuseHost` adopts the resulting FD.

This is why `tokimo.guest_listens=0` is set on the ch cmdline: the guest
*connects out* for everything, matching the Windows HCS path semantics.

## Kernel artifact

The ch backend uses the **same** `.vm/base/vmlinuz` bzImage that the
bwrap/macOS/Windows backends use, fetched by
`scripts/linux/fetch-vm.sh` from the `vm-kernel-*` release.
Cloud Hypervisor v36+ accepts bzImage directly (no PVH ELF required),
and the initrd loads `vmw_vsock_virtio_transport` early at boot so the
host↔init vsock handshake completes without a custom kernel.

There is intentionally no separate `vmlinuz-ch` artifact, no
`bin/ch-vmlinux/`, and no `release-ch-vmlinux.yml`. If you ever do need
a custom kernel for debugging, drop a `vmlinuz` of your choice into
`.vm/base/vmlinuz`.

## Runtime binaries (`bin/`)

The ch backend resolves two host-side binaries from `bin/` (gitignored
— fetch them with `scripts/linux/fetch-ch-deps.sh`):

| Path                                              | Source                                                         |
|---|---|
| `bin/cloud-hypervisor/current/bin/cloud-hypervisor` | upstream `cloud-hypervisor/cloud-hypervisor` release           |
| `bin/cloud-hypervisor/current/bin/ch-remote`        | upstream `cloud-hypervisor/cloud-hypervisor` release           |
| `bin/virtiofsd/current/virtiofsd`                   | this repo's `virtiofsd-v*` release (see `.github/workflows/virtiofsd.yml`) |

## Selecting the backend

Set via `SANDBOX_BACKEND` (see `src/backend_kind.rs`):

| `SANDBOX_BACKEND` | Behavior |
|---|---|
| unset (default) | `Auto` — probe ch, fall back to bwrap, hard-error if both unavailable |
| `auto` | same as unset |
| `ch` | force ch — no fallback |
| `bwrap` | force bwrap — no fallback |
| `disabled` | refuse to provide a backend |

The probe used by `Auto` is `linux::ch::probe::probe_ch()` — purely read-only
filesystem and process-group checks (KVM device, vhost-vsock device,
cloud-hypervisor + virtiofsd binaries, kernel artifact).

## Process inventory per session

| Process | Role |
|---|---|
| `cloud-hypervisor` | KVM VMM |
| `virtiofsd` | vhost-user filesystem serving `<vm_dir>/rootfs/` as tag `work` |
| `tokimo-sandbox-init` (in guest) | PID 1 control plane |
| `tokimo-sandbox-fuse` (in guest, per mount) | FUSE → vsock bridge |
| `tokimo-tun-pump` (in guest) | smoltcp ↔ kernel tk0 bridge (egress) |

All host children are owned by the `ChVm` struct and reaped on drop.

## Testing

```bash
# fetch base artifacts (kernel + initrd + rootfs)
scripts/linux/fetch-vm.sh

# fetch ch runtime binaries (cloud-hypervisor + virtiofsd) into bin/.
scripts/linux/fetch-ch-deps.sh

# build the guest binaries that init.sh will exec
cargo build --bin tokimo-sandbox-init --bin tokimo-sandbox-fuse

# run the public integration suite under ch
PATH="$PWD/target/debug:$PATH" \
    SANDBOX_BACKEND=ch \
    cargo test -- --test-threads=1
```

`--test-threads=1` is required for the same reason it is on macOS: many
fixtures share `.vm/base/` and the VMM startup is not cheap.

## Known limitations

- IPv6 egress depends on the host network; if the host has no v6 route the
  `tests/network.rs` v6 cases fail under both `bwrap` and `ch`.
