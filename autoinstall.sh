#!/bin/bash

# Mirror Terminal output to Workstation
exec > >(tee -a /var/log/autoinstall.log /dev/tty | bash -c 'cat > /dev/tcp/192.168.1.181/9000' 2>/dev/null || true) 2>&1
echo -e "Starting Logger...\n"

# Safeguards to abort installation if something goes wrong
set -Eeuo pipefail

echo -e "Starting Automated Arch Linux Installer...\n"

# Assuming laptop has a single disk, fetch the interface name
DISK_INTERFACE=$(lsblk -dpno NAME | grep -E '^/dev/(nvme[0-9]n[0-9]|sd[a-z]|vd[a-z]|mmcblk[0-9])$' | head -n 1)

# Check if drive was actually found
if [ -z "${DISK_INTERFACE}" ] || [ "${DISK_INTERFACE}" == "/dev/" ]; then
    echo -e "CRITICAL ERROR: No drive found. Cancelling.\n"
    exit 1
fi
echo -e "Found drive at ${DISK_INTERFACE}\n"

# Check if drive is an NVME or SD Card
if [[ "${DISK_INTERFACE}" == *"nvme"* ]] || [[ "${DISK_INTERFACE}" == *"mmcblk"* ]]; then
    # Set Part Suffix e.g. nvme0n1p1
    PART_SUFFIX="p"
else
    # No Part Suffix e.g. sdb1
    PART_SUFFIX=""
fi

# Wipe drive and create a 512MB boot EFI partition, using the remainder for the root partition
echo -e "Wiping Disk ${DISK_INTERFACE}\n"
sgdisk --zap-all "${DISK_INTERFACE}"
echo -e "Creating EFI Partition\n"
sgdisk --clear --new=1:0:+512M --typecode=1:ef00 "${DISK_INTERFACE}"
echo -e "Creating Root Partition\n"
sgdisk --new=2:0:0 --typecode=2:8300 "${DISK_INTERFACE}"

# Define the EFI and Root Partitions
EFI_PART=${DISK_INTERFACE}${PART_SUFFIX}1
ROOT_PART=${DISK_INTERFACE}${PART_SUFFIX}2

# Force the kernel to re-read the partition table
echo -e "Reloading Partition Table\n"
partprobe ${DISK_INTERFACE}

# Wait for udev to create the nodes
echo -e "Waiting for node creation\n"
udevadm settle

# Wait 5 seconds to catch up
echo -e "Waiting 5 seconds\n"
sleep 5

# Format the EFI partition in FAT32 and the root partition in EXT4
echo -e "Formatting EFI Partition\n"
mkfs.fat -F32 "${EFI_PART}"
echo -e "Formatting Root Partition\n"
mkfs.ext4 -F "${ROOT_PART}"

# Mount the two partitions
echo -e "Mounting Root Partition\n"
mount "${ROOT_PART}" /mnt
echo -e "Creating Boot Directory\n"
mkdir -p /mnt/boot
echo -e "Mounting Boot Partition\n"
mount "${EFI_PART}" /mnt/boot

# Install the bare minimum
echo -e "Installing Base Packages\n"
pacstrap /mnt base linux linux-firmware amd-ucode grub lvm2 base-devel efibootmgr openssh python sudo networkmanager

# Generate fstab
echo -e "Generating fstab\n"
genfstab -U /mnt >> /mnt/etc/fstab

# Change root and configure
echo -e "Chrooting to new root and configuring...\n"
arch-chroot /mnt /bin/bash << 'INNER_EOF'

# Safety mesaure for new shell
set -Eeuo pipefail

echo -e "Setting timezone\n"
# Set Timezone
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

echo -e "Setting Hardware Clock Time\n"
# Set Hardware Clock from System Clock
hwclock --systohc

echo -e "Setting Locales\n"
# Set locales
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen

echo -e "Generating Locales\n"
# Generate locale
locale-gen

echo -e "Setting Language\n"
# Set language
echo "LANG=en_US.UTF-8" > /etc/locale.conf

echo -e "Keyboard Configuration\n"
# Set keyboard configuration
echo "KEYMAP=us" > /etc/vconsole.conf

echo -e "Setting Hostname\n"
# Set hostname
echo "laptop_arch_001" > /etc/hostname

echo -e "Enabling Parallel Downloads\n"
# Enable Parallel Downloading to speed up provision
sed -i 's/^#ParallelDownloads.*/ParallelDownloads = 10/' /etc/pacman.conf

echo -e "Installing Additional Packages\n"
# Install a few more packages
pacman -Syu --noconfirm --needed gnome gnome-extra networkmanager fail2ban iptables wireless-regdb firefox featherpad

echo -e "Enabling gdm\n"
# Enable Gnome Display Manager
systemctl enable gdm.service

echo -e "Setting Wi-Fi Regulatory domain\n"
# Set Wireless Regulatory Domain
echo "WIRELESS_REGDOM=\"US\"" > /etc/conf.d/wireless-regdom

echo -e "Enabling NetworkManager\n"
# Enable NetworkManager
systemctl enable NetworkManager

echo -e "Enabling sshd\n"
# Enable SSH
systemctl enable sshd

echo -e "Installing GRUB\n"
# Install Bootloader (GRUB)
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB --removable --recheck
grub-mkconfig -o /boot/grub/grub.cfg

echo -e "Creating user\n"
useradd -m -G wheel -s /bin/bash jhu_admin
# Add password
echo "jhu_admin:mssi_demo2026" | chpasswd

echo -e "Setting up Ansible\n"
# Ansible User Setup
useradd -r -m -G wheel -s /bin/bash ansible_user
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheel_nopasswd
mkdir -p /home/ansible_user/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA0lyqIoVrSgc3IlwYrCJt2zhjAJKFGtOyPvMlHXlHk8 ansible@workstation" > /home/ansible_user/.ssh/authorized_keys
chown -R ansible_user:ansible_user /home/ansible_user/.ssh
chmod 700 /home/ansible_user/.ssh
chmod 600 /home/ansible_user/.ssh/authorized_keys
INNER_EOF

echo -e "Installation complete.\n"
echo -e "Rebooting in 5 seconds...\n"
sleep 5
echo -e "Rebooting...\n"
reboot