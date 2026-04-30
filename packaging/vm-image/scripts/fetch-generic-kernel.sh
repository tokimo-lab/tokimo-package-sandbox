#!/usr/bin/env bash
# Fetches Debian trixie generic linux-image-amd64 .deb (vmlinuz from the
# signed package, modules from the unsigned package — that is how Debian
# splits things since trixie). Extracts vmlinuz + the small set of modules
# we need (Hyper-V vsock + 9p) into the output dir.
#
# Usage: bash fetch-generic-kernel.sh /path/to/output-dir
set -euo pipefail

OUT="${1:?usage: $0 OUTPUT_DIR}"
mkdir -p "$OUT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

MIRROR="${MIRROR:-https://mirrors.tuna.tsinghua.edu.cn/debian}"
KVER="${KVER:-6.12.73+deb13}"

echo "==> resolving package URLs..."
curl -sL "$MIRROR/dists/trixie/main/binary-amd64/Packages.gz" -o pkgs.gz
gunzip pkgs.gz
SIGNED_PATH=$(awk -v want="linux-image-${KVER}-amd64" \
      'BEGIN{flag=0} /^Package: /{flag=($2==want)} flag && /^Filename:/{print $2; exit}' \
      pkgs)
UNSIGNED_PATH=$(awk -v want="linux-image-${KVER}-amd64-unsigned" \
      'BEGIN{flag=0} /^Package: /{flag=($2==want)} flag && /^Filename:/{print $2; exit}' \
      pkgs)
[ -n "$SIGNED_PATH" ]   || { echo "FATAL: signed package not found"   >&2; exit 1; }
[ -n "$UNSIGNED_PATH" ] || { echo "FATAL: unsigned package not found" >&2; exit 1; }

fetch() {
  local url="$1" stem="$2"
  echo "==> downloading $url"
  curl --fail -L -o "${stem}.deb" "$MIRROR/$url"
  mkdir -p "${stem}_ar" "extracted-${stem}"
  ( cd "${stem}_ar" && ar x "../${stem}.deb" )
  tar -C "extracted-${stem}" -xf "${stem}_ar"/data.tar.*
}

fetch "$SIGNED_PATH"   signed
fetch "$UNSIGNED_PATH" unsigned

KSRC="extracted-signed/boot/vmlinuz-${KVER}-amd64"
[ -f "$KSRC" ] || KSRC="extracted-unsigned/boot/vmlinuz-${KVER}-amd64"
[ -f "$KSRC" ] || { echo "FATAL: vmlinuz missing"; ls extracted-*/boot 2>/dev/null; exit 1; }
cp -v "$KSRC" "$OUT/vmlinuz"

MODSRC="extracted-unsigned/usr/lib/modules/${KVER}-amd64"
[ -d "$MODSRC" ] || MODSRC="extracted-unsigned/lib/modules/${KVER}-amd64"
[ -d "$MODSRC" ] || { echo "FATAL: modules dir missing"; find extracted-unsigned -name modules -type d 2>/dev/null; exit 1; }

WANT_RE='hv_sock|hv_utils|hv_vmbus|hv_storvsc|hv_netvsc|hyperv|vmw_vsock|vsock\.ko|9p\.ko|9pnet|fuse|netfs'
mkdir -p "$OUT/modules"
echo "==> selecting modules..."
find "$MODSRC" -name '*.ko*' | grep -E "$WANT_RE" | while read -r m; do
  cp -v "$m" "$OUT/modules/" || true
done

# Also copy modules.dep + modules.alias for runtime probing if available.
for f in modules.dep modules.alias modules.builtin modules.order; do
  [ -f "$MODSRC/$f" ] && cp "$MODSRC/$f" "$OUT/modules/" || true
done

echo "==> done. kernel + $(ls "$OUT/modules" | wc -l) module files at $OUT"
