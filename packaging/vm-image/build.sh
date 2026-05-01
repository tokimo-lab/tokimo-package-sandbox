#!/usr/bin/env bash
# Build TokimoOS: kernel + initrd + rootfs
# Output: ./tokimo-os-{arch}/
#         ├── vmlinuz       # Linux kernel
#         ├── initrd.img    # initramfs with busybox + init.sh
#         └── rootfs/       # Debian 13 rootfs
#
# Usage: bash build.sh [amd64|arm64]
set -euo pipefail

ARCH="${1:-${TOKIMO_ARCH:-amd64}}"

case "$ARCH" in
  amd64|x86_64)
    DOCKER_PLATFORM="linux/amd64"
    DEB_MULTIARCH="x86_64-linux-gnu"
    ;;
  arm64|aarch64)
    DOCKER_PLATFORM="linux/arm64"
    DEB_MULTIARCH="aarch64-linux-gnu"
    ;;
  *)
    echo "error: unsupported arch '$ARCH' (amd64, arm64)"
    exit 1
    ;;
esac

CONTAINER_NAME="tokimo-builder-${ARCH}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$PROJECT_DIR/tokimo-os-${ARCH}"
ROOTFS_DIR="$OUTPUT_DIR/rootfs"
ROOTFS_TAR="$PROJECT_DIR/rootfs.tar"
BUSYBOX_APPLETS="sh mount umount cat echo poweroff sync chroot mkdir ls base64 insmod cp chmod udhcpc ip"

# Optional: path to a prebuilt static `tokimo-sandbox-init` (musl) that
# will be baked into the initrd at /bin/tokimo-sandbox-init. The init.sh
# expects this binary in session-mode (Windows HCS). If unset, the boot
# bundle will be one-shot capable only.
TOKIMO_INIT_BIN="${TOKIMO_INIT_BIN:-}"

echo "==> [1/6] Cleaning old build..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
rm -rf "$OUTPUT_DIR" "$ROOTFS_TAR"

echo "==> [2/6] Starting build container (debian:13 ${DOCKER_PLATFORM})..."
docker run -dit \
  --name "$CONTAINER_NAME" \
  --platform "$DOCKER_PLATFORM" \
  debian:13 bash

echo "==> [3/6] Installing packages (kernel + busybox + runtimes)..."
docker exec -i \
  -e ARCH="$ARCH" \
  -e DEB_MULTIARCH="$DEB_MULTIARCH" \
  -e KERNEL_PKG="linux-image-${ARCH}" \
  "$CONTAINER_NAME" bash << 'BUILDER_SCRIPT'
set -euo pipefail

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl

# Install everything using upstream Debian mirrors (CI runners are overseas;
# the China mirror would be slower from there). The China mirror config is
# written into the image AFTER all installs (see "China mirrors" section
# below) so end-users in China still get fast updates.

apt-get update -qq

DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  gnupg vim nano less procps \
  wget git jq unzip zip bzip2 xz-utils zstd \
  iputils-ping rsync \
  dnsutils ffmpeg \
  python3 python3-pip python3-venv \
  bash-completion \
  pandoc poppler-utils qpdf tesseract-ocr \
  libreoffice-writer libreoffice-impress libreoffice-calc \
  lua5.4 \
  busybox-static \
  gcc libc6-dev \
  kmod \
  $KERNEL_PKG

curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
corepack enable

groupadd -g 1000 tokimo
useradd -m -u 1000 -g 1000 -s /bin/bash -d /home/tokimo tokimo

# Use upstream npm registry for the install itself (fast on overseas CI).
npm config set --global prefix /home/tokimo
npm install -g pnpm docx pptxgenjs

ln -sf ../../bin/python3 /usr/local/bin/python
ln -sf ../../bin/lua5.4 /usr/local/bin/lua

# pip uses upstream PyPI for the install too.
mkdir -p /home/tokimo/python_packages
pip3 install --break-system-packages --target=/home/tokimo/python_packages \
  requests ipython rich \
  pypdf pdfplumber reportlab pytesseract pdf2image \
  pandas openpyxl "markitdown[pptx]" Pillow

# ---------------------------------------------------------------------------
# China mirrors (write AFTER installs, so the image ships with fast mirrors
# for end-users in China without slowing down the CI build).
# ---------------------------------------------------------------------------
rm -f /etc/apt/sources.list.d/debian.sources
cat > /etc/apt/sources.list << 'APTEOF'
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie main contrib non-free non-free-firmware
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie-updates main contrib non-free non-free-firmware
deb https://mirrors.tuna.tsinghua.edu.cn/debian-security trixie-security main contrib non-free non-free-firmware
APTEOF

cat > /etc/pip.conf << 'PIPEOF'
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
trusted-host = pypi.tuna.tsinghua.edu.cn
PIPEOF

npm config set --global registry https://registry.npmmirror.com

echo "TokimoOS" > /etc/hostname

cat > /etc/os-release << 'OSEOF'
PRETTY_NAME="TokimoOS 1.0"
NAME="TokimoOS"
ID=tokimoos
ID_LIKE=debian
VERSION_ID="1.0"
HOME_URL="https://tokimo.io"
OSEOF

cat > /etc/profile.d/tokimo_env.sh << 'ENVEOF'
export HOME=/home/tokimo
export USER=tokimo
export LOGNAME=tokimo
export NPM_CONFIG_PREFIX=/home/tokimo
export NODE_PATH=/home/tokimo/lib/node_modules
export PATH=/home/tokimo/bin:/usr/local/bin:/usr/bin:/bin
export PYTHONPATH=/home/tokimo/python_packages${PYTHONPATH:+:$PYTHONPATH}
export PIP_TARGET=/home/tokimo/python_packages
export npm_config_registry=https://registry.npmmirror.com
ENVEOF
chmod +x /etc/profile.d/tokimo_env.sh

cat > /etc/bash.bashrc << 'BASHRCEOF'
for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done
unset f
[ -f ~/.bashrc ] && . ~/.bashrc
BASHRCEOF

cat > /home/tokimo/.bashrc << 'DOTBASHRC'
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoredups:erasedups
shopt -s histappend

PS1='[\[\033[35;1m\]\u\[\033[0m\]@\[\033[31;1m\]TokimoOS\[\033[0m\]:\[\033[32;1m\]$PWD\[\033[0m\]]\$ '

alias ls='ls --color=auto'
alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias grep='grep --color=auto'

if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion 2>/dev/null || true
fi
DOTBASHRC

cat > /home/tokimo/.bash_profile << 'DOTPROFILE'
[ -f ~/.bashrc ] && . ~/.bashrc
DOTPROFILE

cat > /home/tokimo/.inputrc << 'DOTINPUTRC'
set completion-ignore-case on
set show-all-if-ambiguous on
set show-all-if-unmodified on
set colored-stats on
set mark-symlinked-directories on
set visible-stats on
DOTINPUTRC

chown -R tokimo:tokimo /home/tokimo

# =============================================
# Slim down
# =============================================

rm -rf /usr/include/node
rm -rf /usr/share/perl /usr/share/perl5 /etc/perl

echo "/usr/lib/${DEB_MULTIARCH}/pulseaudio" > /etc/ld.so.conf.d/pulseaudio.conf
echo "/usr/lib/libreoffice/program" > /etc/ld.so.conf.d/libreoffice.conf
ldconfig

rm -rf /usr/bin/scalar /usr/share/man/man1/scalar* 2>/dev/null || true
apt-get remove -y dirmngr gpgsm 2>/dev/null || true

rm -rf /usr/share/vim/vim*/doc /usr/share/vim/vim*/tutor
find /usr/share/vim/vim*/syntax -type f ! -name 'markdown.vim' ! -name 'text.vim' \
  ! -name 'help.vim' ! -name 'vim.vim' ! -name 'viminfo.vim' \
  ! -name 'sh.vim' ! -name 'bash.vim' ! -name 'python.vim' \
  ! -name 'json.vim' ! -name 'yaml.vim' ! -name 'xml.vim' \
  ! -name 'html.vim' ! -name 'css.vim' ! -name 'javascript.vim' \
  ! -name 'conf.vim' ! -name 'gitcommit.vim' ! -name 'gitconfig.vim' \
  ! -name 'diff.vim' ! -name 'csv.vim' ! -name 'toml.vim' \
  ! -name 'sql.vim' ! -name 'log.vim' ! -name 'dosini.vim' \
  ! -name 'cmake.vim' ! -name 'make.vim' \
  ! -name 'lua.vim' \
  -delete 2>/dev/null || true

rm -rf /usr/lib/systemd /usr/lib/init /etc/systemd /etc/init.d
rm -rf /var/lib/systemd /usr/lib/tmpfiles.d /usr/lib/sysctl.d
rm -rf /usr/lib/udev /etc/udev 2>/dev/null || true

rm -rf /usr/share/icons /usr/share/pixmaps /usr/share/applications
rm -rf /usr/share/menu /usr/share/polkit-1
rm -rf /usr/share/fish /usr/share/zsh

rm -rf /usr/share/keyrings /usr/share/gcc /usr/share/libgcrypt20
rm -rf /usr/share/cmake /usr/share/pkgconfig /usr/share/binfmts
rm -rf /usr/share/libc-bin /usr/share/readline /usr/share/misc
rm -rf /usr/share/bug /usr/share/doc-base /usr/share/debconf
rm -rf /usr/share/debianutils /usr/share/base-files /usr/share/base-passwd
rm -rf /usr/share/gdb /usr/share/gitweb /usr/share/tabset
rm -rf /usr/share/python-wheels

rm -rf /etc/pam.d /etc/pam.conf /etc/security /usr/share/pam*
rm -rf /var/lib/pam
rm -rf /etc/cron* /etc/logrotate.d /etc/logcheck /etc/default /etc/skel
rm -rf /usr/lib/lsb /usr/lib/valgrind /usr/lib/mime

find /usr/sbin -type f ! -name 'ldconfig' ! -name 'update-ca-certificates' \
  ! -name 'zic' ! -name 'sysctl' ! -name 'iconvconfig' -delete 2>/dev/null || true

find /usr/share/terminfo -type f ! -path '*/xterm*' -delete 2>/dev/null || true
find /usr/share/terminfo -type d -empty -delete 2>/dev/null || true

find /usr/share/zoneinfo -type f \
  ! -path '*/Asia/*' ! -name 'UTC' ! -name 'PRC' ! -name 'posixrules' \
  -delete 2>/dev/null || true
find /usr/share/zoneinfo -type d -empty -delete 2>/dev/null || true

# Stage kernel modules (initrd needs them) BEFORE removing them from rootfs.
# The module-bundle step on the host does `docker cp /var/cache/tokimo-kmods/.` out.
KVER_INNER=$(ls /lib/modules | head -1)
KMOD_LIST='hv_vmbus hv_utils vsock hv_sock scsi_common scsi_mod scsi_transport_fc hv_storvsc sd_mod netfs 9pnet 9pnet_fd 9p crc16 crc32c_generic libcrc32c jbd2 mbcache ext4 hv_netvsc failover net_failover'
# macOS VZ uses virtio-vsock + virtio-net (not Hyper-V). Add the virtio
# transport modules for arm64 so the init binary can load them in the
# guest VM. virtio_net requires net_failover (already listed) for SR-IOV
# fallback handling.
if [ "$ARCH" = "arm64" ]; then
    KMOD_LIST="$KMOD_LIST vmw_vsock_virtio_transport virtio_net"
fi
resolve_deps() {
    local mod="$1" seen="$2"
    case " $seen " in *" $mod "*) echo "$seen"; return 0;; esac
    seen="$seen $mod"
    local depline
    depline=$(modinfo -F depends -k "$KVER_INNER" "$mod" 2>/dev/null || true)
    if [ -n "$depline" ]; then
        local IFS=','
        for d in $depline; do
            [ -z "$d" ] && continue
            seen=$(resolve_deps "$d" "$seen")
        done
    fi
    echo "$seen"
}
ALL_MODS=''
for m in $KMOD_LIST; do ALL_MODS=$(resolve_deps "$m" "$ALL_MODS"); done
mkdir -p /var/cache/tokimo-kmods
for m in $ALL_MODS; do
    f=$(modinfo -F filename -k "$KVER_INNER" "$m" 2>/dev/null || true)
    [ -z "$f" ] && continue
    [ ! -f "$f" ] && continue
    base=$(basename "$f")
    case "$base" in
        *.ko.xz) xz -d -c "$f" > /var/cache/tokimo-kmods/${base%.xz} ;;
        *.ko)    cp "$f" /var/cache/tokimo-kmods/$base ;;
    esac
done
echo "    staged $(ls /var/cache/tokimo-kmods | wc -l) kernel modules to /var/cache/tokimo-kmods"

# Remove kernel modules from rootfs (saves space; initrd has copies)
find /lib/modules -name '*.ko*' -delete 2>/dev/null || true
rm -rf /lib/modules/*/kernel 2>/dev/null || true

rm -rf \
  /usr/share/man \
  /usr/share/doc \
  /usr/share/locale \
  /usr/share/info \
  /usr/share/lintian \
  /usr/share/common-licenses

apt-get clean
rm -rf \
  /var/lib/apt/lists/* \
  /var/cache/apt \
  /var/log/apt \
  /var/log/*.log \
  /root/.npm \
  /root/.cache \
  /home/tokimo/.cache \
  /tmp/* \
  /var/tmp/*

find / -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find / -name '*.pyc' -delete 2>/dev/null || true

echo "--- verification ---"
node --version
python3 --version
python --version
lua -v
pandoc --version | head -1
busybox 2>&1 | head -1 || true
ls /boot/ | grep vmlinuz || echo "no kernel in /boot"
BUILDER_SCRIPT

echo "==> [4/6] Extracting kernel + busybox..."
mkdir -p "$OUTPUT_DIR"

KERNEL_PATH=$(docker exec "$CONTAINER_NAME" sh -c 'ls /boot/vmlinuz-* 2>/dev/null | head -1')
if [ -z "$KERNEL_PATH" ]; then
    echo "ERROR: kernel not found in container"
    docker rm -f "$CONTAINER_NAME"
    exit 1
fi
echo "    kernel: $KERNEL_PATH"

docker cp "$CONTAINER_NAME:$KERNEL_PATH" "$OUTPUT_DIR/vmlinuz"
docker cp "$CONTAINER_NAME:/bin/busybox" "$OUTPUT_DIR/busybox"
chmod +x "$OUTPUT_DIR/busybox"

echo "    vmlinuz: $(du -sh "$OUTPUT_DIR/vmlinuz" | cut -f1)"
echo "    busybox: $(du -sh "$OUTPUT_DIR/busybox" | cut -f1)"

echo "==> [5/6] Building initrd..."
INITRD_DIR="$PROJECT_DIR/initrd-${ARCH}"
rm -rf "$INITRD_DIR"
mkdir -p "$INITRD_DIR/bin" "$INITRD_DIR/proc" "$INITRD_DIR/sys" "$INITRD_DIR/dev" "$INITRD_DIR/mnt/work" "$INITRD_DIR/tmp" "$INITRD_DIR/sbin"

cp "$OUTPUT_DIR/busybox" "$INITRD_DIR/bin/busybox"
chmod +x "$INITRD_DIR/bin/busybox"

for applet in $BUSYBOX_APPLETS; do
    ln -sf busybox "$INITRD_DIR/bin/$applet"
done
ln -sf /bin/busybox "$INITRD_DIR/sbin/poweroff"
ln -sf /bin/busybox "$INITRD_DIR/sbin/init"
ln -sf /bin/busybox "$INITRD_DIR/sbin/udhcpc"

# udhcpc default script (busybox style).
mkdir -p "$INITRD_DIR/etc/udhcpc"
cat > "$INITRD_DIR/etc/udhcpc/default.script" <<'UDHCPC_SCRIPT'
#!/bin/busybox sh
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
UDHCPC_SCRIPT
chmod +x "$INITRD_DIR/etc/udhcpc/default.script"

cp "$PROJECT_DIR/init.sh" "$INITRD_DIR/init"
chmod +x "$INITRD_DIR/init"

# --- vsock support for Windows HCS ---
# HCS exposes Plan9 shares via vsock (Hyper-V sockets), not virtio devices.
# The Debian *generic* (linux-image-amd64) kernel ships hv_vmbus / vsock /
# hv_sock as loadable modules — init.sh insmods them at boot. The cloud
# kernel is too stripped down (no vsock at all). We bundle the modules
# along with vsock9p into the initrd.

echo "    compiling vsock9p static helper..."
docker cp "$PROJECT_DIR/vsock9p.c" "$CONTAINER_NAME:/tmp/vsock9p.c"
docker exec "$CONTAINER_NAME" gcc -static -O2 -o /tmp/vsock9p /tmp/vsock9p.c
docker cp "$CONTAINER_NAME:/tmp/vsock9p" "$INITRD_DIR/bin/vsock9p"
chmod +x "$INITRD_DIR/bin/vsock9p"
echo "    vsock9p: $(du -sh "$INITRD_DIR/bin/vsock9p" | cut -f1)"

echo "    bundling kernel modules (Hyper-V vsock + SCSI + 9p + ext4 + deps)..."
KMODS_HOST="$INITRD_DIR/modules"
mkdir -p "$KMODS_HOST"
docker cp "$CONTAINER_NAME:/var/cache/tokimo-kmods/." "$KMODS_HOST/"
echo "    modules: $(ls "$KMODS_HOST" | wc -l) files"

# --- bake tokimo-sandbox-init (Rust musl static) into initrd if provided ---
if [ -n "$TOKIMO_INIT_BIN" ] && [ -f "$TOKIMO_INIT_BIN" ]; then
    echo "    embedding tokimo-sandbox-init: $TOKIMO_INIT_BIN ($(du -sh "$TOKIMO_INIT_BIN" | cut -f1))"
    cp "$TOKIMO_INIT_BIN" "$INITRD_DIR/bin/tokimo-sandbox-init"
    chmod +x "$INITRD_DIR/bin/tokimo-sandbox-init"
elif [ -f "$PROJECT_DIR/initrd-prep/tokimo-sandbox-init" ]; then
    echo "    embedding tokimo-sandbox-init from initrd-prep/"
    cp "$PROJECT_DIR/initrd-prep/tokimo-sandbox-init" "$INITRD_DIR/bin/tokimo-sandbox-init"
    chmod +x "$INITRD_DIR/bin/tokimo-sandbox-init"
else
    echo "    NOTE: tokimo-sandbox-init not provided; session-mode bundles will not work."
    echo "    Set TOKIMO_INIT_BIN=/path/to/tokimo-sandbox-init or place it at initrd-prep/."
fi

echo "    packing initrd..."
( cd "$INITRD_DIR" && find . | cpio -o -H newc 2>/dev/null ) | gzip -9 > "$OUTPUT_DIR/initrd.img"

echo "    initrd.img: $(du -sh "$OUTPUT_DIR/initrd.img" | cut -f1)"
rm -rf "$INITRD_DIR"

echo "==> [6/6] Exporting rootfs..."
docker export "$CONTAINER_NAME" -o "$ROOTFS_TAR"
echo "    rootfs.tar: $(du -sh "$ROOTFS_TAR" | cut -f1)"

mkdir -p "$ROOTFS_DIR"
tar -xpf "$ROOTFS_TAR" \
  -C "$ROOTFS_DIR" \
  --numeric-owner \
  --no-same-owner \
  --exclude='./dev/*' \
  --exclude='./proc/*' \
  --exclude='./sys/*'

# Remove kernel files from rootfs (already extracted above)
rm -f "$ROOTFS_DIR"/boot/vmlinuz-* "$ROOTFS_DIR"/boot/initrd.img-* "$ROOTFS_DIR"/boot/System.map-* "$ROOTFS_DIR"/boot/config-* 2>/dev/null || true
# Remove root-level symlinks created by kernel package post-install
rm -f "$ROOTFS_DIR"/vmlinuz "$ROOTFS_DIR"/vmlinuz.old "$ROOTFS_DIR"/initrd.img "$ROOTFS_DIR"/initrd.img.old 2>/dev/null || true

# Copy busybox into rootfs for sandbox use
cp "$OUTPUT_DIR/busybox" "$ROOTFS_DIR/bin/busybox"
for applet in $BUSYBOX_APPLETS; do
    [ ! -e "$ROOTFS_DIR/bin/$applet" ] && ln -sf busybox "$ROOTFS_DIR/bin/$applet" || true
done

echo "--- final ---"
ls -lh "$OUTPUT_DIR/vmlinuz" "$OUTPUT_DIR/initrd.img"
echo "rootfs: $(du -sh "$ROOTFS_DIR" | cut -f1)"
echo "rootfs has busybox: $( [ -f "$ROOTFS_DIR/bin/busybox" ] && echo yes || echo no )"

echo "==> Cleaning up..."
docker rm -f "$CONTAINER_NAME"
rm -f "$ROOTFS_TAR"

echo ""
echo "Done! Output: $OUTPUT_DIR"
echo "  vmlinuz    ($(du -sh "$OUTPUT_DIR/vmlinuz" | cut -f1))"
echo "  initrd.img ($(du -sh "$OUTPUT_DIR/initrd.img" | cut -f1))"
echo "  rootfs/    ($(du -sh "$ROOTFS_DIR" | cut -f1))"
echo ""
echo "Install: bash install.sh ${ARCH}"
