#!/bin/busybox sh
# tokimo-sandbox initrd init (PID 1)
# Local-dev copy. The authoritative copy is packaging/vm-image/init.sh — keep
# them in sync until the local-dev flow is consolidated.

set -e

/bin/busybox mount -t proc proc /proc 2>/dev/null || true
/bin/busybox mount -t sysfs sys /sys 2>/dev/null || true
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null || true

CMDLINE=$(/bin/busybox cat /proc/cmdline 2>/dev/null || echo)
echo "tokimo-init: cmdline=$CMDLINE" >/dev/kmsg 2>/dev/null || true

CMD_B64=""
ROOTSHARE_PORT=""
WORK_PORT=""
SESSION_MODE=0
INIT_PORT=50003
for arg in $CMDLINE; do
    case "$arg" in
        run=*)                       CMD_B64="${arg#run=}" ;;
        tokimo.rootshare_port=*)     ROOTSHARE_PORT="${arg#tokimo.rootshare_port=}" ;;
        tokimo.work_port=*)          WORK_PORT="${arg#tokimo.work_port=}" ;;
        tokimo.session=1)            SESSION_MODE=1 ;;
        tokimo.init_port=*)          INIT_PORT="${arg#tokimo.init_port=}" ;;
    esac
done

if [ "$SESSION_MODE" = 0 ] && [ -z "$CMD_B64" ]; then
    echo "tokimo-init: missing run= and not session mode" >/dev/kmsg 2>/dev/null || true
    /bin/busybox poweroff -f
fi

/bin/busybox mkdir -p /mnt/work /newroot

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
    load_mod hv_vmbus
    load_mod hv_utils
    load_mod vsock
    load_mod hv_sock
    # SCSI stack: scsi_common provides helper symbols pulled out of scsi_mod
    # in modern kernels — must load before scsi_mod.
    load_mod scsi_common
    load_mod scsi_mod
    load_mod scsi_transport_fc
    load_mod hv_storvsc
    load_mod sd_mod
    load_mod netfs
    load_mod 9pnet
    load_mod 9pnet_fd
    load_mod 9p
    # ext4 needs crc16 + crc32c + libcrc32c + jbd2 + mbcache.
    load_mod crc16
    load_mod crc32c_generic
    load_mod libcrc32c
    load_mod jbd2
    load_mod mbcache
    load_mod ext4
    echo "tokimo-init: modules loaded" >/dev/kmsg 2>/dev/null || true
fi

MOUNTED_ROOT=0

if /bin/busybox mount -t virtiofs work /newroot 2>/dev/null; then
    echo "tokimo-init: virtiofs rootfs mounted (macOS VZ mode)" >/dev/kmsg 2>/dev/null || true
    /bin/busybox mkdir -p /newroot/mnt/work
    /bin/busybox mount --bind /newroot /newroot/mnt/work 2>/dev/null || true
    MOUNTED_ROOT=1
fi

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
        if [ -n "$WORK_PORT" ] && [ -x /bin/vsock9p ]; then
            /bin/busybox mkdir -p /newroot/mnt/work
            /bin/vsock9p /newroot/mnt/work "$WORK_PORT" work 2>/dev/null || true
        fi
        MOUNTED_ROOT=1
    else
        echo "tokimo-init: SCSI mount $ROOT_DEVICE failed" >/dev/kmsg 2>/dev/null || true
    fi
fi

if [ "$MOUNTED_ROOT" = 0 ] && [ -n "$ROOTSHARE_PORT" ] && [ -n "$WORK_PORT" ]; then
    if [ -x /bin/vsock9p ]; then
        if /bin/vsock9p /newroot "$ROOTSHARE_PORT" rootshare; then
            echo "tokimo-init: rootshare mounted on vsock port $ROOTSHARE_PORT" >/dev/kmsg 2>/dev/null || true
            /bin/busybox mkdir -p /newroot/mnt/work
            if /bin/vsock9p /newroot/mnt/work "$WORK_PORT" work; then
                echo "tokimo-init: work share mounted on vsock port $WORK_PORT" >/dev/kmsg 2>/dev/null || true
                MOUNTED_ROOT=1
            else
                echo "tokimo-init: work share mount failed" >/dev/kmsg 2>/dev/null || true
            fi
        else
            echo "tokimo-init: rootshare mount failed" >/dev/kmsg 2>/dev/null || true
        fi
    else
        echo "tokimo-init: /bin/vsock9p missing" >/dev/kmsg 2>/dev/null || true
    fi
fi

if [ "$MOUNTED_ROOT" = 0 ]; then
    echo "tokimo-init: no shared filesystem available, powering off" >/dev/kmsg 2>/dev/null || true
    /bin/busybox poweroff -f
fi

/bin/busybox mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/run /newroot/tmp 2>/dev/null || true
/bin/busybox mount --bind /proc /newroot/proc 2>/dev/null || /bin/busybox mount -t proc proc /newroot/proc
/bin/busybox mount --bind /sys  /newroot/sys  2>/dev/null || /bin/busybox mount -t sysfs sys /newroot/sys
/bin/busybox mount --bind /dev  /newroot/dev  2>/dev/null || /bin/busybox mount -t devtmpfs dev /newroot/dev
/bin/busybox mount -t tmpfs tmpfs /newroot/tmp 2>/dev/null || true
/bin/busybox mount -t tmpfs tmpfs /newroot/run 2>/dev/null || true

/bin/busybox mkdir -p /newroot/run/tk-sandbox 2>/dev/null || true

if [ "$SESSION_MODE" = 1 ]; then
    echo "tokimo-init: SESSION mode — exec'ing tokimo-sandbox-init under chroot" >/dev/kmsg 2>/dev/null || true

    if [ -x /bin/tokimo-sandbox-init ]; then
        /bin/busybox cp /bin/tokimo-sandbox-init /newroot/bin/tokimo-sandbox-init
        /bin/busybox chmod +x /newroot/bin/tokimo-sandbox-init
    elif [ ! -x /newroot/bin/tokimo-sandbox-init ]; then
        echo "tokimo-init: tokimo-sandbox-init missing in initramfs and rootfs" >/dev/kmsg 2>/dev/null || true
        /bin/busybox poweroff -f
    fi

    export TOKIMO_SANDBOX_VSOCK_PORT="$INIT_PORT"
    export TOKIMO_SANDBOX_PRE_CHROOTED=1
    exec /bin/busybox chroot /newroot /bin/tokimo-sandbox-init </dev/null >/dev/null 2>/dev/kmsg
    echo "tokimo-init: chroot exec failed" >/dev/kmsg 2>/dev/null || true
    /bin/busybox poweroff -f
fi

CMD=$(echo "$CMD_B64" | /bin/busybox base64 -d 2>/dev/null || echo "$CMD_B64")
echo "tokimo-init: exec: $CMD" >/dev/kmsg 2>/dev/null || true

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
