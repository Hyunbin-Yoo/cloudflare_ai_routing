# Download Arch Linux ISO
$ curl -L -o /tmp/archlinux-x86_64.iso https://mirror.rackspace.com/archlinux/iso/latest/archlinux-x86_64.iso
# Download its SHA-256 hash
$ curl -L -o /tmp/sha256sums.txt https://mirror.rackspace.com/archlinux/iso/latest/sha256sums.txt

# Confirm ISO Integrity without using cd, instead using pipes
$ grep "archlinux-x86_64.iso" /tmp/sha256sums.txt | sed 's|archlinux-x86_64.iso|/tmp/archlinux-x86_64.iso|' | sha256sum -c -
/tmp/archlinux-x86_64.iso: OK

# Mount the Arch ISO
$ sudo mount -o loop /tmp/archlinux-x86_64.iso /mnt

# Copy the kernel, initramfs, and squashfs OS images to provisioning server
$ sudo sudo mkdir -p /srv/http/provision
$ sudo cp /mnt/arch/boot/x86_64/vmlinuz-linux /srv/http/provision/vmlinuz-linux
$ sudo cp /mnt/arch/boot/x86_64/initramfs-linux.img /srv/http/provision/initramfs-linux.img
$ sudo cp -r /mnt/arch /srv/http/provision/arch

# Unmount the ISO
$ sudo umount /mnt

# Clean up temporary files
$ rm /tmp/archlinux-x86_64.iso /tmp/sha256sums.txt