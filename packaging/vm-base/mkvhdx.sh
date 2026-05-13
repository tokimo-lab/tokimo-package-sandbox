set -e
apt-get update -qq && apt-get install -y -qq e2fsprogs qemu-utils tar >/dev/null
mkdir -p /tmp/rootfs
echo "extracting rootfs.tar..."
tar -xpf /input/rootfs.tar -C /tmp/rootfs --exclude=./dev/* --exclude=./proc/* --exclude=./sys/*
rm -f /tmp/rootfs/vmlinuz* /tmp/rootfs/initrd.img* /tmp/rootfs/boot/vmlinuz-* /tmp/rootfs/boot/initrd.img-* /tmp/rootfs/boot/System.map-* /tmp/rootfs/boot/config-* 2>/dev/null || true
for a in sh mount umount cat echo poweroff sync chroot mkdir ls base64 insmod cp chmod udhcpc ip; do
  if [ ! -e /tmp/rootfs/bin/$a ]; then ln -sf busybox /tmp/rootfs/bin/$a; fi
done
echo "creating image (${IMG_MB}MB) with conservative ext4..."
qemu-img create -f raw /tmp/rootfs.img ${IMG_MB}M >/dev/null
# Disable features that older guest kernels may not have:
# -O ^64bit  -> stay 32-bit (works on all kernels)
# -O ^metadata_csum -> no per-block checksums (some kernels reject)
# -O ^huge_file ^extra_isize ^flex_bg ^uninit_bg ^dir_nlink (older defaults)
mkfs.ext4 -F -L tokimo-rootfs -O "^64bit,^metadata_csum,^huge_file,^flex_bg,^extra_isize,^uninit_bg,^dir_nlink,^orphan_file" -d /tmp/rootfs /tmp/rootfs.img
echo "converting to vhdx..."
qemu-img convert -f raw -O vhdx -o subformat=dynamic /tmp/rootfs.img /out/rootfs.vhdx
echo DONE