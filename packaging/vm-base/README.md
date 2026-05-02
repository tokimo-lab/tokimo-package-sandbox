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
| `build.sh`           | Full build (debootstrap + busybox + kernel + initrd + vhdx). Slow (~20 min on amd64, ~25 min on arm64 with QEMU). Used by `.github/workflows/vm-base.yml`. |
| `init.sh`            | PID 1 inside the initrd (busybox shell). Loads kernel modules, mounts shares, chroots into rootfs, exec's `tokimo-sandbox-init`. |
| `docker-modify.sh`   | One-shot tweaks applied inside the build container (mirrors, slim-down). |
| `vsock9p.c`          | Static helper that connects to a vsock port and mounts Plan9 from the resulting fd. |
| `../vm/scripts/fetch-generic-kernel.sh` | Pulls Debian's `linux-image-amd64` `.deb`, extracts vmlinuz + relevant modules. Used by alternative kernel-only flows; not part of vm-base. |
| `../vm/scripts/repack-initrd.sh` | Local WSL-side repack of the prep dir → initrd.img. Used in dev. |
| `../vm/scripts/rebake-initrd.sh` | **The fast path.** Takes an existing base initrd (no init binary) + a freshly-built `tokimo-sandbox-init` and produces a final initrd. Used by both `vm-image.yml` and the local dev wrapper. |

## Two-layer build model

```
                ┌──────────────────────────────┐
                │  vm-base.yml  (slow, rare)   │
                │   debootstrap + kernel deb   │
                │   → vm-base-v1.0.0 release   │
                └──────────────┬───────────────┘
                               │  base initrd (no init bin)
                               │  rootfs.vhdx, rootfs.tar.zst
                               ▼
                ┌──────────────────────────────┐
                │  vm-image.yml (fast, often)  │
                │   cargo build init binary    │
                │   vm/scripts/rebake-initrd.sh │
                │   → vm-v1.9.0 release        │
                └──────────────┬───────────────┘
                               ▼
                       scripts/windows/fetch-vm.ps1
                       vm/{vmlinuz,initrd.img,rootfs.vhdx}
```

The same `rebake-initrd.sh` is used locally — see
`scripts/windows/rebake-initrd.ps1` at the repo root — so the dev loop after editing
`tokimo-sandbox-init` Rust sources is `cargo build` + cpio repack only,
never debootstrap.
