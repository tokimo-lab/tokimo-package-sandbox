#!/usr/bin/env bash
# build-ch-initrd.sh — build a minimal initrd.cpio.gz for Cloud Hypervisor microVMs.
#
# The resulting initrd contains:
#   /init               tokimo-guest-agent (musl static binary, runs as PID 1)
#   /proc /sys /dev     empty directories (guest-agent mounts them at startup)
#   /tmp                empty directory
#   /bin/busybox        static busybox binary (optional, if <busybox-binary> supplied)
#   /bin/{sh,echo,cat,ls,ip,udhcpc,wget,cut,ipcalc} symlinks -> busybox
#
# Usage:
#   ./scripts/linux/build-ch-initrd.sh <out.cpio.gz> <agent-binary> [busybox-binary]
#
# Example (called from Makefile):
#   ./scripts/linux/build-ch-initrd.sh \
#       ../../bin/ch-initrd/dev/linux-x86_64/initrd.cpio.gz \
#       target/x86_64-unknown-linux-musl/release/tokimo-guest-agent \
#       target/initrd-deps/busybox
#
# Requirements:
#   python3, gzip — standard on any modern Linux host (no cpio binary needed).
#
# PoC note: this script is called locally.  Production initrds will be built
# in CI as GitHub Actions artifacts released with tokimo-package-sandbox tags.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <out.cpio.gz> <agent-binary> [busybox-binary]" >&2
    exit 1
fi

OUT="$1"
AGENT="$2"
BUSYBOX="${3:-}"

if [ ! -f "$AGENT" ]; then
    echo "build-ch-initrd: agent binary not found: $AGENT" >&2
    exit 1
fi

# Verify the agent binary is statically linked.
if command -v file &>/dev/null; then
    file_out=$(file "$AGENT")
    if echo "$file_out" | grep -q "dynamically linked"; then
        echo "build-ch-initrd: ERROR: $AGENT is dynamically linked — must be statically linked musl binary" >&2
        exit 1
    fi
fi

if [ -n "$BUSYBOX" ]; then
    if [ ! -f "$BUSYBOX" ]; then
        echo "build-ch-initrd: busybox binary not found: $BUSYBOX" >&2
        exit 1
    fi
    if command -v file &>/dev/null; then
        bb_file=$(file "$BUSYBOX")
        if echo "$bb_file" | grep -q "dynamically linked"; then
            echo "build-ch-initrd: ERROR: $BUSYBOX is dynamically linked — must be static" >&2
            exit 1
        fi
    fi
fi

mkdir -p "$(dirname "$OUT")"

# Use Python to create the newc cpio archive (avoids requiring cpio binary).
python3 - "$AGENT" "$OUT" "$BUSYBOX" <<'PYEOF'
import sys
import os
import gzip

def _pad4(n):
    """Return number of padding bytes needed to align n to a 4-byte boundary."""
    r = n % 4
    return (4 - r) % 4

def newc_entry(ino, name, data=b"", mode=0o100755, uid=0, gid=0, nlink=1, mtime=0,
               devmajor=0, devminor=0, rdevmajor=0, rdevminor=0):
    """Return bytes for a single newc cpio entry."""
    name_bytes = name.encode() + b"\x00"
    namesize = len(name_bytes)
    filesize = len(data)

    header = (
        b"070701"
        + (
            f"{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}"
            f"{filesize:08x}{devmajor:08x}{devminor:08x}{rdevmajor:08x}"
            f"{rdevminor:08x}{namesize:08x}{'00000000'}"
        ).encode()
    )

    # Pad name to 4-byte boundary (from start of header which is 110 bytes).
    name_pad = _pad4(110 + namesize)
    # Pad data to 4-byte boundary.
    data_pad = _pad4(filesize)

    return header + name_bytes + bytes(name_pad) + data + bytes(data_pad)

def newc_symlink(ino, name, target):
    """Return bytes for a newc cpio symlink entry."""
    # mode 0o120777: S_IFLNK (0o120000) | rwxrwxrwx (0o777)
    return newc_entry(ino, name, data=target.encode(), mode=0o120777, nlink=1)


agent_path  = sys.argv[1]
out_path    = sys.argv[2]
busybox_path = sys.argv[3] if len(sys.argv) > 3 else ""

with open(agent_path, "rb") as f:
    agent_data = f.read()

busybox_data = b""
if busybox_path:
    with open(busybox_path, "rb") as f:
        busybox_data = f.read()

entries = []
ino = 1

# . (root directory)
entries.append(newc_entry(ino, ".", mode=0o040755, nlink=2))
ino += 1

# Empty directories that guest-agent mounts into, plus minimal config dirs.
for d in ("dev", "proc", "sys", "tmp", "etc", "etc/udhcpc"):
    entries.append(newc_entry(ino, d, mode=0o040755, nlink=2))
    ino += 1

# /init — the guest-agent binary.
entries.append(newc_entry(ino, "init", data=agent_data, mode=0o0100755))
ino += 1

listing = [".", "dev", "proc", "sys", "tmp", "etc", "etc/udhcpc", "init"]

if busybox_data:
    # /bin and /sbin directories
    entries.append(newc_entry(ino, "bin", mode=0o040755, nlink=2))
    ino += 1
    listing.append("bin")
    entries.append(newc_entry(ino, "sbin", mode=0o040755, nlink=2))
    ino += 1
    listing.append("sbin")

    # /bin/busybox — the static binary
    entries.append(newc_entry(ino, "bin/busybox", data=busybox_data, mode=0o0100755))
    ino += 1
    listing.append("bin/busybox")

    # Symlinks: /bin/{sh,echo,cat,ls,ip,udhcpc,wget,cut,ipcalc} -> busybox
    for applet in ("sh", "echo", "cat", "ls", "ip", "udhcpc", "wget", "cut", "ipcalc"):
        entries.append(newc_symlink(ino, f"bin/{applet}", "busybox"))
        ino += 1
        listing.append(f"bin/{applet}")

    entries.append(newc_symlink(ino, "sbin/udhcpc", "/bin/busybox"))
    ino += 1
    listing.append("sbin/udhcpc")

    udhcpc_script = b'''#!/bin/busybox sh
RESOLV_CONF=/etc/resolv.conf
[ -n "$1" ] || { echo "Error: should be called from udhcpc" >&2; exit 1; }
case "$1" in
    deconfig)
        /bin/busybox ip addr flush dev "$interface" 2>/dev/null
        /bin/busybox ip link set "$interface" up
        ;;
    bound|renew)
        /bin/busybox ip addr flush dev "$interface" 2>/dev/null
        if [ -n "$subnet" ]; then
            mask=$(/bin/busybox ipcalc -p 0.0.0.0 "$subnet" 2>/dev/null | /bin/busybox cut -d= -f2)
            [ -z "$mask" ] && mask=24
            /bin/busybox ip addr add "$ip/$mask" dev "$interface"
        else
            /bin/busybox ip addr add "$ip/24" dev "$interface"
        fi
        if [ -n "$router" ]; then
            for r in $router; do
                /bin/busybox ip route add default via "$r" dev "$interface" 2>/dev/null
            done
        fi
        : > "$RESOLV_CONF"
        [ -n "$domain" ] && echo "search $domain" >> "$RESOLV_CONF"
        for dns in $dns; do
            echo "nameserver $dns" >> "$RESOLV_CONF"
        done
        ;;
esac
exit 0
'''
    entries.append(newc_entry(ino, "etc/udhcpc/default.script", data=udhcpc_script, mode=0o0100755))
    ino += 1
    listing.append("etc/udhcpc/default.script")

# TRAILER (end of archive sentinel).
entries.append(newc_entry(0, "TRAILER!!!", mode=0, nlink=1))

cpio_bytes = b"".join(entries)

with gzip.open(out_path, "wb", compresslevel=9) as gz:
    gz.write(cpio_bytes)

# Listing for verification.
print(f"build-ch-initrd: wrote {out_path} ({os.path.getsize(out_path) / 1024:.0f} KB)")
print("build-ch-initrd: contents:")
for name in listing:
    print(f"  ./{name}")
PYEOF

echo "build-ch-initrd: done."
