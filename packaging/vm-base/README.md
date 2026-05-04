# packaging/vm-base — Linux VM image build (rootfs + kernel + initrd)

This directory contains the build pipeline for the Debian-based Linux VM
image consumed by tokimo-package-sandbox at runtime:

* **Windows HCS** — `vmlinuz` + `initrd.img` + `rootfs.vhdx`
* **macOS VZ** (arm64) — `vmlinuz` + `initrd.img` + `rootfs.tar.zst`
* **Linux bwrap** — `rootfs.tar.zst` (chroot template)

The `tokimo-sandbox-init` source (in `src/bin/tokimo-sandbox-init/`) and the
image that bakes it are versioned together in this repo, so a single tag pins
both halves.

## Layout

| File | Purpose |
|------|---------|
| `build.sh`           | Full build (debootstrap + busybox + kernel + initrd + vhdx). ~20 min on amd64, ~25 min on arm64 with QEMU. Used by `.github/workflows/vm.yml`. |
| `init.sh`            | PID 1 inside the initrd (busybox shell). Loads kernel modules, mounts shares, chroots into rootfs, exec's `tokimo-sandbox-init`. |
| `docker-modify.sh`   | One-shot tweaks applied inside the build container (mirrors, slim-down). |
| `vsock9p.c`          | Static helper that connects to a vsock port and mounts Plan9 from the resulting fd. |
| `../vm/scripts/fetch-generic-kernel.sh` | Pulls Debian's `linux-image-amd64` `.deb`, extracts vmlinuz + relevant modules. Used by alternative kernel-only flows; not part of vm-base. |
| `../vm/scripts/repack-initrd.sh` | Local WSL-side repack of the prep dir → initrd.img. Used in dev. |
| `../vm/scripts/rebake-initrd.sh` | Takes an existing base initrd + a freshly-built `tokimo-sandbox-init` / `tokimo-sandbox-fuse` and produces a final initrd. Used by `vm.yml` (to add the fuse binary on top of `build.sh`'s output) and by the local dev wrapper. |

## Build flow

```
                ┌──────────────────────────────────────────┐
                │   .github/workflows/vm.yml                │
                │                                           │
                │   ① cargo build (init + tun-pump + fuse)  │
                │   ② build.sh ${arch}                      │
                │       └── debootstrap + kernel + initrd   │
                │           with init+tun-pump baked in     │
                │   ③ rebake-initrd.sh (adds fuse)          │
                │   ④ pack vmlinuz / initrd / rootfs        │
                │   → vm-v1.9.0 release                     │
                └──────────────────┬───────────────────────┘
                                   ▼
                         scripts/windows/fetch-vm.ps1
                         vm/{vmlinuz,initrd.img,rootfs.vhdx}
```

For local dev after editing `tokimo-sandbox-init` Rust sources, the loop is
`cargo build` + `rebake-initrd.sh` against a previously downloaded base
initrd — no debootstrap needed.
