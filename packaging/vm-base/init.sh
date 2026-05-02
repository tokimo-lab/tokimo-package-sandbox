#!/bin/busybox sh
# tokimo-sandbox initrd init (PID 1)
#
# Boot model:
#   * macOS VZ:  workspace_dir is mounted as `work` via virtio-fs and
#                also serves as the rootfs (chroot target). Single share.
#   * Windows HCS: SCSI VHDX rootfs + FUSE-over-vsock for user mounts.
#     The guest mounts the VHDX at /newroot, bind-mounts /proc /sys /dev
#     /run, then switch_root and exec. User mounts are handled at runtime
#     by tokimo-sandbox-init via MountFuse ops.
#
# Output goes to /mnt/work/.vz_{stdout,stderr,exit_code} (relative to the
# rootfs after switch_root). The host reads them after the VM powers off.

set -e

/bin/busybox mount -t proc proc /proc 2>/dev/null || true
/bin/busybox mount -t sysfs sys /sys 2>/dev/null || true
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null || true

CMDLINE=$(/bin/busybox cat /proc/cmdline 2>/dev/null || echo)
echo "tokimo-init: cmdline=$CMDLINE" >/dev/kmsg 2>/dev/null || true

# Parse kernel cmdline.
CMD_B64=""
SESSION_MODE=0
INIT_PORT=50003
NETSTACK_PORT=""
GUEST_LISTENS=0
NETDNS=on
for arg in $CMDLINE; do
    case "$arg" in
        run=*)                       CMD_B64="${arg#run=}" ;;
        tokimo.session=1)            SESSION_MODE=1 ;;
        tokimo.init_port=*)          INIT_PORT="${arg#tokimo.init_port=}" ;;
        tokimo.netstack_port=*)      NETSTACK_PORT="${arg#tokimo.netstack_port=}" ;;
        tokimo.guest_listens=1)      GUEST_LISTENS=1 ;;
        tokimo.netdns=*)             NETDNS="${arg#tokimo.netdns=}" ;;
    esac
done

if [ "$SESSION_MODE" = 0 ] && [ -z "$CMD_B64" ]; then
    echo "tokimo-init: missing run= and not session mode" >/dev/kmsg 2>/dev/null || true
    /bin/busybox poweroff -f
fi

/bin/busybox mkdir -p /mnt/work /newroot

# ---------------------------------------------------------------------------
# Load kernel modules from /modules (Hyper-V vsock + FUSE stack).
# Order matters: hv_vmbus first, then vsock + hv_sock + FUSE.
# ---------------------------------------------------------------------------
load_mod() {
    local m="/modules/$1.ko"
    [ -f "$m" ] || { echo "tokimo-init: missing module $1" >/dev/kmsg 2>/dev/null; return 0; }
    if /bin/busybox insmod "$m" 2>/tmp/_insmod.err; then
        echo "tokimo-init: insmod $1 OK" >/dev/kmsg 2>/dev/null
    else
        echo "tokimo-init: insmod $1 FAILED: $(/bin/busybox cat /tmp/_insmod.err)" >/dev/kmsg 2>/dev/null
    fi
}

if [ -d /modules ]; then
    # Hyper-V transport.
    load_mod hv_vmbus
    load_mod hv_utils
    # vsock core then hv_sock transport.
    load_mod vsock
    load_mod hv_sock
    # macOS VZ vsock transport — virtio-vsock. No-op on Windows where the
    # .ko isn't present in /modules.
    load_mod vmw_vsock_virtio_transport_common
    load_mod vmw_vsock_virtio_transport
    # SCSI stack (for VHDX boot disk). scsi_common provides helper symbols
    # split out of scsi_mod in modern kernels — must load before scsi_mod.
    # scsi_transport_fc is pulled in by hv_storvsc.
    load_mod scsi_common
    load_mod scsi_mod
    load_mod scsi_transport_fc
    load_mod hv_storvsc
    load_mod sd_mod
    # Hyper-V network virtual service client (synthetic NIC).
    # Optional: only present when the initrd was rebaked with networking
    # support. failover/net_failover are pulled in by netvsc when SR-IOV
    # is configured but are harmless to load eagerly.
    load_mod failover
    load_mod net_failover
    load_mod hv_netvsc
    # macOS VZ NAT NIC (virtio-net). No-op on Windows where the .ko isn't
    # present in /modules.
    load_mod virtio_net
    # ext4 filesystem (for SCSI rootfs). Needs crc16 + crc32c + libcrc32c
    # + jbd2 + mbcache.
    load_mod crc16
    load_mod crc32c_generic
    load_mod libcrc32c
    load_mod jbd2
    load_mod mbcache
    load_mod ext4
    # FUSE (for tokimo-sandbox-fuse over vsock — used by both Linux and
    # macOS dynamic mounts). `fuse` is the core; some kernels split out
    # `fuse_core` and require it to be loaded first.
    load_mod fuse
    echo "tokimo-init: modules loaded" >/dev/kmsg 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Mount shared filesystems.
# ---------------------------------------------------------------------------

MOUNTED_ROOT=0

# macOS VZ path: virtio-fs single `work` share, used as both rootfs and work.
if /bin/busybox mount -t virtiofs work /newroot 2>/dev/null; then
    echo "tokimo-init: virtiofs rootfs mounted (macOS VZ mode)" >/dev/kmsg 2>/dev/null || true
    /bin/busybox mkdir -p /newroot/mnt/work
    /bin/busybox mount --bind /newroot /newroot/mnt/work 2>/dev/null || true
    MOUNTED_ROOT=1
fi

# Windows HCS path: SCSI VHDX boot disk (cowork-style).
# If the kernel cmdline says root=/dev/sda and the device exists, mount it.
ROOT_DEVICE=""
for arg in $CMDLINE; do
    case "$arg" in
        root=/dev/*) ROOT_DEVICE="${arg#root=}" ;;
    esac
done
if [ "$MOUNTED_ROOT" = 0 ] && [ -n "$ROOT_DEVICE" ] && [ -b "$ROOT_DEVICE" ]; then
    ROOTFSTYPE="ext4"
    for arg in $CMDLINE; do
        case "$arg" in
            rootfstype=*) ROOTFSTYPE="${arg#rootfstype=}" ;;
        esac
    done
    if /bin/busybox mount -t "$ROOTFSTYPE" -o rw "$ROOT_DEVICE" /newroot 2>/dev/null; then
        echo "tokimo-init: SCSI rootfs mounted from $ROOT_DEVICE ($ROOTFSTYPE)" >/dev/kmsg 2>/dev/null || true
        /bin/busybox mkdir -p /newroot/mnt/work
        MOUNTED_ROOT=1
    else
        echo "tokimo-init: SCSI mount $ROOT_DEVICE failed" >/dev/kmsg 2>/dev/null || true
    fi
fi

if [ "$MOUNTED_ROOT" = 0 ]; then
    echo "tokimo-init: no shared filesystem available, powering off" >/dev/kmsg 2>/dev/null || true
    /bin/busybox poweroff -f
fi

# ---------------------------------------------------------------------------
# Bind essential filesystems into the new root.
# ---------------------------------------------------------------------------

/bin/busybox mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/run /newroot/tmp 2>/dev/null || true
/bin/busybox mount --bind /proc /newroot/proc 2>/dev/null || /bin/busybox mount -t proc proc /newroot/proc
/bin/busybox mount --bind /sys  /newroot/sys  2>/dev/null || /bin/busybox mount -t sysfs sys /newroot/sys
/bin/busybox mount --bind /dev  /newroot/dev  2>/dev/null || /bin/busybox mount -t devtmpfs dev /newroot/dev
# UNIX98 pseudo-terminals: bare devtmpfs has no /dev/pts, and many minimal
# kernels don't expose /dev/ptmx as a static node — `posix_openpt` then
# returns ENOENT. Mount devpts with ptmxmode so /dev/pts/ptmx is usable
# and provide a /dev/ptmx symlink as a fallback for callers using the
# legacy path.
/bin/busybox mkdir -p /newroot/dev/pts 2>/dev/null || true
/bin/busybox mount -t devpts -o gid=5,mode=620,ptmxmode=666 devpts /newroot/dev/pts 2>/dev/null || true
if ! [ -e /newroot/dev/ptmx ]; then
    /bin/busybox ln -sf /dev/pts/ptmx /newroot/dev/ptmx 2>/dev/null || true
fi
/bin/busybox mount -t tmpfs tmpfs /newroot/tmp 2>/dev/null || true
/bin/busybox mount -t tmpfs tmpfs /newroot/run 2>/dev/null || true

# ---------------------------------------------------------------------------
# Decode and run the command inside the rootfs (chrooted).
# ---------------------------------------------------------------------------

# Bind /run as tmpfs inside the rootfs so the init binary can create
# /run/tk-sandbox/control.sock if it falls back to that path.
/bin/busybox mkdir -p /newroot/run/tk-sandbox 2>/dev/null || true

if [ "$SESSION_MODE" = 1 ]; then
    echo "tokimo-init: SESSION mode — exec'ing tokimo-sandbox-init under chroot" >/dev/kmsg 2>/dev/null || true

    # ---------------------------------------------------------------------------
    # Network bring-up.
    #
    # The userspace netstack (host-side smoltcp) is **always-on**: the
    # host runs a smoltcp gateway over a vsock-bridged TAP device `tk0`
    # regardless of `NetworkPolicy`. Egress filtering happens on the host
    # via `EgressPolicy`. `tokimo.netdns=on` is set when upstream DNS /
    # default routes should also be configured inside the guest;
    # `tokimo.netdns=off` (NetworkPolicy::Blocked) leaves /etc/resolv.conf
    # alone and skips the default routes so the guest cannot resolve or
    # dial anything outside the gateway IPs.
    # ---------------------------------------------------------------------------
    /bin/busybox ip link set lo up 2>/dev/null || true
    if [ -n "$NETSTACK_PORT" ]; then
        echo "tokimo-init: configuring tk0 via userspace netstack (vsock port $NETSTACK_PORT, dns=$NETDNS)" \
            >/dev/kmsg 2>/dev/null || true

        load_mod tun || true
        if [ ! -e /dev/net/tun ]; then
            /bin/busybox mkdir -p /dev/net
            /bin/busybox mknod /dev/net/tun c 10 200 2>/dev/null || true
            /bin/busybox chmod 0666 /dev/net/tun
        fi

        if [ -x /bin/tokimo-tun-pump ]; then
            # tun-pump creates tk0 via TUNSETIFF, then dials the host. Run
            # it in the background; it lives until the VM dies or the
            # host's netstack thread shuts down.
            /bin/tokimo-tun-pump "$NETSTACK_PORT" >/dev/kmsg 2>&1 &
        else
            echo "tokimo-init: tokimo-tun-pump missing — netstack disabled" \
                >/dev/kmsg 2>/dev/null || true
        fi

        # Wait for tk0 to appear (tun-pump's TUNSETIFF creates it).
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            [ -d /sys/class/net/tk0 ] && break
            /bin/busybox sleep 0.1 2>/dev/null || /bin/busybox usleep 100000 2>/dev/null || true
        done

        if [ -d /sys/class/net/tk0 ]; then
            /bin/busybox ip link set tk0 address 02:00:00:00:00:02 2>/dev/null || true
            /bin/busybox ip addr add 192.168.127.2/24 dev tk0 2>/dev/null || true
            /bin/busybox ip link set tk0 up 2>/dev/null || true
            # IPv6: enable on tk0, assign ULA. Disable DAD/RA BEFORE
            # assigning the address — DAD would otherwise delay the
            # address ~1 s in "tentative" state.
            echo 0 > /proc/sys/net/ipv6/conf/tk0/disable_ipv6 2>/dev/null || true
            echo 0 > /proc/sys/net/ipv6/conf/tk0/accept_dad 2>/dev/null || true
            echo 0 > /proc/sys/net/ipv6/conf/tk0/dad_transmits 2>/dev/null || true
            echo 0 > /proc/sys/net/ipv6/conf/tk0/accept_ra 2>/dev/null || true
            /bin/busybox ip -6 addr add fd00:7f::2/64 dev tk0 2>/dev/null || true

            if [ "$NETDNS" = "on" ]; then
                /bin/busybox ip route add default via 192.168.127.1 dev tk0 2>/dev/null || true
                /bin/busybox ip -6 route add default via fd00:7f::1 dev tk0 2>/dev/null || true
                echo "nameserver 1.1.1.1" > /newroot/etc/resolv.conf 2>/dev/null || true
                echo "nameserver 8.8.8.8" >> /newroot/etc/resolv.conf 2>/dev/null || true
            fi
            # Even with NETDNS=off, the /24 directly-attached route from
            # `ip addr add` covers traffic to the gateway IP itself.
        else
            echo "tokimo-init: tk0 did not appear" >/dev/kmsg 2>/dev/null || true
        fi
    else
        echo "tokimo-init: NETSTACK_PORT unset — no network" >/dev/kmsg 2>/dev/null || true
    fi

    # Always copy a fresh tokimo-sandbox-init from initramfs into the rootfs
    # so a stale binary doesn't get reused across builds.
    if [ -x /bin/tokimo-sandbox-init ]; then
        /bin/busybox cp /bin/tokimo-sandbox-init /newroot/bin/tokimo-sandbox-init
        /bin/busybox chmod +x /newroot/bin/tokimo-sandbox-init
    elif [ ! -x /newroot/bin/tokimo-sandbox-init ]; then
        echo "tokimo-init: tokimo-sandbox-init missing in initramfs and rootfs" >/dev/kmsg 2>/dev/null || true
        /bin/busybox poweroff -f
    fi

    # Same for tokimo-sandbox-fuse: tokimo-sandbox-init spawns it as
    # /bin/tokimo-sandbox-fuse from inside the chroot, so it must be
    # present under /newroot/bin/.
    if [ -x /bin/tokimo-sandbox-fuse ]; then
        /bin/busybox cp /bin/tokimo-sandbox-fuse /newroot/bin/tokimo-sandbox-fuse
        /bin/busybox chmod +x /newroot/bin/tokimo-sandbox-fuse
    fi

    # The init binary listens on AF_VSOCK port $INIT_PORT for the
    # host-side service to connect via AF_HYPERV. Kernel console is on
    # /dev/ttyS1 (COM2) for diagnostics; ttyS0 is unused.
    #
    # We use `exec` so init.sh's PID 1 is replaced by chroot → init
    # binary. The init binary expects to be PID 1 (it checks getpid()==1),
    # which works because chroot is the same PID via exec chain.
    export TOKIMO_SANDBOX_VSOCK_PORT="$INIT_PORT"
    # init.sh always pre-chroots; init binary should skip its own mount/chroot.
    export TOKIMO_SANDBOX_PRE_CHROOTED=1
    if [ "$GUEST_LISTENS" = 1 ]; then
        # macOS VZ: guest listens for host connect on AF_VSOCK.
        export TOKIMO_SANDBOX_GUEST_LISTENS=1
    fi
    exec /bin/busybox chroot /newroot /bin/tokimo-sandbox-init </dev/null >/dev/null 2>/dev/kmsg
    # If exec returns, something went wrong.
    echo "tokimo-init: chroot exec failed" >/dev/kmsg 2>/dev/null || true
    /bin/busybox poweroff -f
fi

CMD=$(echo "$CMD_B64" | /bin/busybox base64 -d 2>/dev/null || echo "$CMD_B64")
echo "tokimo-init: exec: $CMD" >/dev/kmsg 2>/dev/null || true

# We `chroot` rather than `switch_root` because some shares (Plan9) are
# mounted into /newroot and switch_root would break the underlying
# mounts. chroot is sufficient for one-shot command execution.
#
# IMPORTANT: do not let `set -e` kill us when the user command exits non-zero.
# Disable errexit just for the chroot block, capture RC, then continue.
set +e
STDIN_FILE=/dev/null
[ -f /newroot/mnt/work/.vz_stdin ] && STDIN_FILE=/newroot/mnt/work/.vz_stdin
/bin/busybox chroot /newroot /bin/bash -c "
    cd /mnt/work 2>/dev/null || true
    exec /bin/bash -c \"\$0\"
" "$CMD" <"$STDIN_FILE" >/newroot/mnt/work/.vz_stdout 2>/newroot/mnt/work/.vz_stderr
RC=$?
set -e

echo "$RC" > /newroot/mnt/work/.vz_exit_code

/bin/busybox sync
echo "tokimo-init: done (exit=$RC)" >/dev/kmsg 2>/dev/null || true
/bin/busybox poweroff -f
