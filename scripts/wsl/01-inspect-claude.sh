#!/usr/bin/env bash
# Phase 1: 检查 Claude Desktop 的 initrd 结构和启动协议
# 在 WSL2 (Ubuntu 22.04) 中以普通用户运行：
#   bash scripts/wsl/01-inspect-claude.sh 2>&1 | tee scripts/wsl/01-inspect.log
#
# 这一步只读 + 解包到临时目录，不会修改任何 Windows 文件，也不需要 sudo。

set -euo pipefail

CLAUDE_BUNDLE="/mnt/c/Users/William/AppData/Local/Claude-3p/vm_bundles/claudevm.bundle"
WORK="/tmp/tokimo-claude-inspect"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "===== 0. 检查依赖 ====="
need=()
for cmd in cpio file zstd xxd strings; do
    command -v "$cmd" >/dev/null 2>&1 || need+=("$cmd")
done
if [ ${#need[@]} -gt 0 ]; then
    echo "缺少命令: ${need[*]}"
    echo "请在 WSL 里手动运行: sudo apt-get install -y cpio file zstd xxd binutils"
    exit 1
fi

mkdir -p "$WORK"
cd "$WORK"

echo "===== 1. 验证文件存在 ====="
ls -la "$CLAUDE_BUNDLE/vmlinuz" "$CLAUDE_BUNDLE/initrd" "$CLAUDE_BUNDLE/rootfs.vhdx" \
    "$CLAUDE_BUNDLE/smol-bin.vhdx" 2>&1 | head -20

echo ""
echo "===== 2. vmlinuz 信息 ====="
file "$CLAUDE_BUNDLE/vmlinuz"
# 提取嵌入的内核版本字符串
strings "$CLAUDE_BUNDLE/vmlinuz" 2>/dev/null | grep -E '^Linux version|^[0-9]+\.[0-9]+\.[0-9]+.+SMP' | head -3 || true

echo ""
echo "===== 3. 解开 initrd ====="
INITRD="$CLAUDE_BUNDLE/initrd"
echo "size: $(stat -c%s "$INITRD") bytes"
# initrd 可能是单个 cpio，也可能是多个 cpio 串联（initramfs 标准）。先看头部 magic。
head -c 6 "$INITRD" | xxd
echo "(magic: 0707 01 = cpio newc)"

mkdir -p initrd-extract
cd initrd-extract

# Multi-segment initramfs: extract all concatenated cpio archives in sequence.
# The decompressor / cpio command stops at the first archive; we need to
# advance past it (4-byte aligned) and re-run cpio for each segment.
python3 - "$INITRD" <<'PY'
import os, sys, struct, gzip, lzma, io, subprocess, shutil
path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()

def detect(b):
    if b[:6] == b"070701" or b[:6] == b"070702" or b[:6] == b"070707":
        return "cpio"
    if b[:2] == b"\x1f\x8b":
        return "gzip"
    if b[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if b[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if b[:3] == b"BZh":
        return "bzip2"
    if b[:4] == b"\x04\x22\x4d\x18":
        return "lz4"
    return None

off = 0
seg = 0
import tempfile
while off < len(data):
    # Skip null padding (alignment)
    while off < len(data) and data[off] == 0:
        off += 1
    if off >= len(data):
        break
    kind = detect(data[off:off+8])
    if kind is None:
        print(f"[seg {seg}] off={off} unknown bytes: {data[off:off+8].hex()}")
        break
    print(f"[seg {seg}] off={off} kind={kind}")
    seg += 1
    seg_dir = f"seg{seg:02d}"
    os.makedirs(seg_dir, exist_ok=True)
    if kind == "cpio":
        # Find the trailing TRAILER!!! marker, then locate end-of-archive.
        # cpio newc records are 110-byte header + name + data, all 4-byte aligned.
        p = off
        while p < len(data):
            if data[p:p+6] not in (b"070701", b"070702"):
                break
            namesize = int(data[p+94:p+102], 16)
            filesize = int(data[p+54:p+62], 16)
            name_off = p + 110
            name_end = name_off + namesize
            # Pad name to 4-byte
            data_off = (name_end + 3) & ~3
            data_end = data_off + filesize
            data_end_padded = (data_end + 3) & ~3
            name = data[name_off:name_end].rstrip(b"\x00").decode("ascii", "replace")
            p = data_end_padded
            if name == "TRAILER!!!":
                break
        seg_data = data[off:p]
        with open(seg_dir + ".cpio", "wb") as o:
            o.write(seg_data)
        subprocess.run(["cpio", "--quiet", "-idm", "--no-absolute-filenames"],
                       cwd=seg_dir, input=seg_data, check=False)
        print(f"  extracted {len(seg_data)} bytes -> {seg_dir}/")
        off = p
    elif kind in ("gzip", "xz", "zstd"):
        # decompress one stream then it's a cpio inside
        if kind == "gzip":
            decomp = gzip.decompress(data[off:])
        elif kind == "xz":
            decomp = lzma.decompress(data[off:])
        else:
            import zstandard as z
            decomp = z.ZstdDecompressor().decompress(data[off:])
        with open(seg_dir + ".cpio", "wb") as o:
            o.write(decomp)
        subprocess.run(["cpio", "--quiet", "-idm", "--no-absolute-filenames"],
                       cwd=seg_dir, input=decomp, check=False)
        print(f"  decompressed {len(decomp)} bytes -> {seg_dir}/")
        # Hard to know where this stream ended in the file; assume one stream at most.
        off = len(data)
    else:
        break
print(f"total segments: {seg}")
PY

# Identify the "main" segment (the one with /init or /sbin/init).
echo ""
echo "--- segment summary ---"
for d in seg*/; do
    has_init=""
    [ -f "$d/init" ] && has_init+="/init "
    [ -f "$d/sbin/init" ] && has_init+="/sbin/init "
    [ -d "$d/lib/modules" ] && has_init+="lib/modules "
    sz=$(du -sh "$d" 2>/dev/null | cut -f1)
    printf "  %-10s  size=%-8s  has=%s\n" "$d" "$sz" "$has_init"
done

# Pick the segment most likely to be the rootfs.
MAIN_SEG=$(ls -d seg*/ 2>/dev/null | while read d; do
    score=0
    [ -f "$d/init" ] && score=$((score+10))
    [ -f "$d/sbin/init" ] && score=$((score+5))
    [ -d "$d/lib/modules" ] && score=$((score+3))
    [ -d "$d/bin" ] && score=$((score+1))
    echo "$score $d"
done | sort -rn | head -1 | awk '{print $2}')
echo "main segment: $MAIN_SEG"
cd "$WORK/initrd-extract/$MAIN_SEG" 2>/dev/null || cd "$WORK/initrd-extract"
echo ""
echo "===== 4. initrd 顶层结构 ====="
ls -la | head -40

echo ""
echo "===== 5. /init 脚本（cowork 启动协议关键） ====="
if [ -f init ]; then
    echo "--- init (size $(stat -c%s init)) ---"
    file init
    head -200 init || cat init
    echo ""
    echo "--- 末尾 80 行 ---"
    tail -80 init
fi

echo ""
echo "===== 6. 关键二进制 ====="
for n in init sbin/init bin/init usr/bin/init lib/systemd/systemd; do
    if [ -e "$n" ] || [ -L "$n" ]; then
        ls -la "$n"
        if [ -f "$n" ] && [ -s "$n" ]; then
            file "$n" 2>/dev/null | head -1
        fi
    fi
done

echo ""
echo "===== 7. 内核模块清单（HV / 9p / vsock / scsi 相关） ====="
find lib/modules -type f \( -name 'hv_*.ko*' -o -name 'vsock*.ko*' -o -name '9p*.ko*' -o \
    -name 'scsi*.ko*' -o -name 'storvsc*.ko*' -o -name 'netfs*.ko*' \) 2>/dev/null | sort

echo ""
echo "===== 8. 查找内核版本目录 ====="
find lib/modules -maxdepth 2 -type d 2>/dev/null | head -10

echo ""
echo "===== 9. Claude 的 init 中引用的 cmdline 参数 ====="
if [ -f init ]; then
    grep -oE '(claude|cowork|root=|init=|console=|loglevel=|ip=|panic=|tokimo|share|vsock|plan9|virtiofs|hostloop|memoryMB|cpu)[a-zA-Z0-9._=/-]*' init | sort -u | head -50
fi

echo ""
echo "===== 10. 关键 /etc 文件（如果存在） ====="
for f in etc/inittab etc/init.d/rcS etc/profile etc/rc.local etc/fstab; do
    if [ -f "$f" ]; then
        echo "--- $f ---"
        cat "$f" | head -40
    fi
done

echo ""
echo "===== 11. 大致总结 ====="
echo "initrd extracted to: $WORK/initrd-extract"
echo "total entries: $(find . -mindepth 1 | wc -l)"
echo "total size:    $(du -sh . | cut -f1)"

echo ""
echo "===== DONE — 请把上面输出全部贴回来 ====="
