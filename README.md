# Cloudflare Workers AI Routing Project
Custom routing solution which utilizes Workers AI of Cloudflare for Students.

## Day 1: Router & Workstation Setup
To have full control of the router, we replace the stock firmware with a open source firmware. I chose [OpenWRT](https://openwrt.org/). I used the [TP-Link Archer C7 AC1750 v5](https://www.tp-link.com/us/home-networking/wifi-router/archer-c7/). I prepared an Arch Linux Workstation which is used to configure the router.

The Router is only connected to the Workstation. It does not have access to either the Internet nor the Intranet at this time. The Workstation currently has a connection to the Internet via other Routers that have already been configured.

### Download Router Firmware
#### GUI Download
Go to [Openwrt Firmware Selector](https://firmware-selector.openwrt.org/) and select the latest version. As of writing, the lastest stable version is **24.10.5**.

[Download the factory image](https://downloads.openwrt.org/releases/24.10.5/targets/ath79/generic/openwrt-24.10.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin).

#### CLI Download
```bash
$ curl https://downloads.openwrt.org/releases/24.10.5/targets/ath79/generic/openwrt-24.10.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin -O
```

#### Confirm Integrity
```bash
$ sha256sum openwrt-24.10.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin 
e3c3209e2a752d4c7710ccfb06ecb4fe76baf243c3ca72629ae5c625538830b3  openwrt-24.10.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin
```

### Prepare TFTP Server on Workstation
#### Prepare the file
```bash
# Create folder in Linux Workstation to deliver firmware via TFTP
$ sudo mkdir -p /srv/tftp

# Copy the firmware to the TFTP folder (Use the exact file name below)
$ sudo cp openwrt-24.10.5-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin /srv/tftp/ArcherC7v5_tp_recovery.bin
$ sudo chmod 644 /srv/tftp/ArcherC7v5_tp_recovery.bin
```

#### Configure the interface
```bash
# Identify the name of the Ethernet interface connected to the router
$ ifconfig

# Remove the current IP address of the interface
$ sudo ip addr flush dev enp7s0f3u2    # replace 'enp7s0f3u2' with your interface name

# Set IP address to 192.168.0.66, which the router expects during TFTP recovery
$ sudo ip addr add 192.168.0.66/24 dev enp7s0f3u2

# Explicitly enable the interface
$ sudo ip link set dev enp7s0f3u2 up
```

#### Configure the TFTP Server
```bash
# Install a TFTP server using your package manager
$ sudo pacman -Syu --needed tftp-hpa

# Configure TFTP
$ sudo bash -c 'echo "TFTPD_ARGS=\"--verbose --user nobody --address 192.168.0.66:69 --secure /srv/tftp\"" > /etc/conf.d/tftpd'

# Start TFTP
$ sudo systemctl start tftpd.service

# Confirm that TFTP is listening on 192.168.0.66:69
$ ss -uln | grep 192.168.0.66:69
UNCONN 0      0         192.168.0.66:69         0.0.0.0:* 

# Monitor TFTP logs (keep this command running)
$ sudo journalctl -u tftpd -f
systemd[1]: Starting hpa's original TFTP daemon...
systemd[1]: Started hpa's original TFTP daemon.
```

### Flash Firmware on Router
+ Power off the router
+ While pressing the reset button, power on the router.
+ Keep holding the reset button until you see the update backlight turn on
+ Let go of the reset button and wait a few minutes

```bash
# TFTP should display new logs
in.tftpd[443311]: RRQ from 192.168.0.86 filename ArcherC7v5_tp_recovery.bin
in.tftpd[443327]: RRQ from 192.168.0.86 filename ArcherC7v5_tp_recovery.bin
```

#### Confirm DHCP Functionality
Once the router reboots and the Ethernet backlight is on, 

```bash
# Remove current IP address of interface since OpenWRT uses 192.168.1.0/24 by default
$ sudo ip addr flush dev enp7s0f3u2    # replace 'enp7s0f3u2' with your interface name

# Restart NetworkManager, which automatically requests a new IP
$ sudo systemctl restart NetworkManager

# Confirm that a 192.168.1.0/24 address is present
$ ip -4 a show dev enp7s0f3u2
21: enp7s0f3u2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.1.181/24 brd 192.168.1.255 scope global dynamic noprefixroute enp7s0f3u2
       valid_lft 43191sec preferred_lft 43191sec
```

### Lock Down Router
#### Create SSH Key
```bash
$ ssh-keygen -t ed25519 -f ~/.ssh/openwrt
```

#### Initial Router Setup
```bash
# Log into Router
$ ssh root@192.168.1.1
BusyBox v1.36.1 (2025-12-17 21:08:22 UTC) built-in shell (ash)

  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 OpenWrt 24.10.5, r29087-d9c5716d1d
 -----------------------------------------------------
=== WARNING! =====================================
There is no root password defined on this device!
Use the "passwd" command to set up a new password
in order to prevent unauthorized SSH logins.
--------------------------------------------------

# Set Administrator Password
root@OpenWrt:~# passwd
root@OpenWrt:~# exit
```

#### Push SSH Key to router
```bash
$ ssh-copy-id -i ~/.ssh/openwrt.pub root@192.168.1.1
```

#### Setup Automatic Key Handling
```bash
# Create SSH Config File
$ cat << 'EOF' >> ~/.ssh/config
Host openwrt
    HostName 192.168.1.1
    User root
    IdentityFile ~/.ssh/openwrt.pub
    IdentitiesOnly yes
EOF

# Set Strict Permissions
$ chmod 600 ~/.ssh/config

# Login with alias
$ ssh openwrt
root@OpenWrt:~#
```

#### Block Password Logins via SSH
```bash

# Disable password authentication on Dropbear (SSH service that OpenWRT uses)
root@OpenWrt:~# uci set dropbear.@dropbear[0].PasswordAuth='off'
root@OpenWrt:~# uci set dropbear.@dropbear[0].RootPasswordAuth='off'

# Commit the change
root@OpenWrt:~# uci commit dropbear

# Load the new settings
root@OpenWrt:~# /etc/init.d/dropbear restart
root@OpenWrt:~# exit
Connection to 192.168.1.1 closed.

# Confirm that Password Logins are blocked in SSH
$ ssh root@192.168.1.1 -o PubkeyAuthentication=no
root@192.168.1.1: Permission denied (publickey).
```

#### Conceal Web Server
```bash
$ ssh openwrt
# Remove public listening ports
root@OpenWrt:~# uci delete uhttpd.main.listen_http
root@OpenWrt:~# uci delete uhttpd.main.listen_https

# Add localhost-only listening ports
root@OpenWrt:~# uci add_list uhttpd.main.listen_http='127.0.0.1:80'
root@OpenWrt:~# uci add_list uhttpd.main.listen_https='127.0.0.1:443'

# Commit the change
root@OpenWrt:~# uci commit uhttpd

# Load the new settings
root@OpenWrt:~# /etc/init.d/uhttpd restart
root@OpenWrt:~# exit
Connection to 192.168.1.1 closed.

# Confirm that the web-based GUI cannot be reached anymore
$ firefox 192.168.1.1
Unable to connect

# Open background tunnel to localhost so that GUI can be accessed only in workstation
$ ssh -f -N -M -S /tmp/openwrt_gui -L 8080:127.0.0.1:80 openwrt

# Confirm that GUI can be accessed from workstation
$ firefox localhost:8080

# Close tunnel
$ ssh -S /tmp/openwrt_gui -O exit openwrt

# Confirm access is once again impossible
$ firefox localhost:8080
```

#### Install Certificate on Router and force HTTPS
```bash
# Install CA packages
$ sudo pacman -Syu --needed mkcert nss

# Generate local CA and install it on trust stores
$ mkcert -install
Created a new local CA
The local CA is now installed in the system trust store!
The local CA is now installed in the Firefox and/or Chrome/Chromium trust store (requires browser restart)!

# Generate certificate specifically for 192.168.1.1 and localhost
$ mkcert 192.168.1.1 localhost 127.0.0.1
Created a new certificate valid for the following names
 - "192.168.1.1"
 - "localhost"
 - "127.0.0.1"

The certificate is at "./192.168.1.1+2.pem" and the key at "./192.168.1.1+2-key.pem"

It will expire on 20 May 2028

$ cp 192.168.1.1+2.pem openwrt.pem
```

```bash
# Convert modern PKCS#8 to older PKCS#1 from Key to make it compatible with OpenWRT
$ openssl pkey -in 192.168.1.1+2-key.pem -traditional -out openwrt-key.pem
```

Modern Linux distributions use SFTP instead of SCP when using the ```scp``` commmand. Since OpenWRT doesn't come with SCP by default, we need to finally connect the Router to the Internet to install the SFTP package. Alternatively, we could have built a custom OpenWRT image that included this specific package, or use ```scp```'s ```-O``` flag, which uses the legacy SCP protocol instead.

```bash
# Install SFTP on Router which is used instead of SCP
$ ssh openwrt
root@OpenWrt:~# opkg update && opkg install openssh-sftp-server
Configuring openssh-sftp-server.

# Push certificate to Router
$ scp openwrt.pem openwrt-key.pem root@openwrt:/etc/

$ ssh openwrt
# Point uHTTP to pushed certificate and key
root@OpenWrt:~# uci set uhttpd.main.cert='/etc/openwrt.pem'
root@OpenWrt:~# uci set uhttpd.main.key='/etc/openwrt-key.pem'

# Redirect HTTP traffic to HTTPS
root@OpenWrt:~# uci set uhttpd.main.redirect_https='1'
root@OpenWrt:~# uci commit uhttpd
root@OpenWrt:~# /etc/init.d/uhttpd restart
root@OpenWrt:~# exit

# Open secure background tunnel
$ ssh -f -N -M -S /tmp/openwrt_gui -L 8443:127.0.0.1:443 openwrt
$ firefox https://localhost:8443
$ ssh -S /tmp/openwrt_gui -O exit openwrt
```

End of Day 1. Locked down the Router and configured secure in-site access. I plan to install a VPN service to enable remote maintenance tomorrow.

## Day 2: Laptop Setup

### Configure Provisioning Environment
Now that the router is locked down both my Workstation and my Laptop are connected to it, through which outbound traffic goes through. The Workstation no longer has a separate connection. I restarted both the Router and the Workstation to confirm that Router settings persist through reboots. I moved the USB-to-Ethernet adapter I am using from the front to the back for stability.

#### Set up Static IP
```bash
# Check IP Address
$ ip -4 a show dev enp7s0f1u3u4    # Interface Name changed because I moved the UtE Adapter to a different port
5: enp7s0f1u3u4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.1.181/24 brd 192.168.1.255 scope global dynamic noprefixroute enp7s0f1u3u4
       valid_lft 41483sec preferred_lft 41483sec
```

Although the Router was rebooted, the Workstation requested the same IP and succeeded. Since PXE requires a fixed address, we will use Static IP to guarantee that the Workstation's IP never changes.

```bash
# Find MAC Address
$ ip link show dev enp7s0f1u3u4
5: enp7s0f1u3u4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether [USB-to-Ethernet Adapter MAC] brd ff:ff:ff:ff:ff:ff

# Configure Static IP on Router
$ ssh openwrt
root@OpenWrt:~# uci add dhcp host
cfg05fe63
root@OpenWrt:~# uci set dhcp.@host[-1].name='workstation-arch'
root@OpenWrt:~# uci set dhcp.@host[-1].mac='[USB-to-Ethernet Adapter MAC]'
root@OpenWrt:~# uci set dhcp.@host[-1].ip='192.168.1.181'
root@OpenWrt:~# uci commit dhcp
root@OpenWrt:~# /etc/init.d/dnsmasq restart
udhcpc: started, v1.36.1
udhcpc: broadcasting discover
udhcpc: no lease, failing
```

#### Meticulously Confirm Static IP is working Server-side
```bash
# Reboot
root@OpenWrt:~# reboot
root@OpenWrt:~# Connection to 192.168.1.1 closed by remote host.
Connection to 192.168.1.1 closed.

# Stop NetworkManager
$ sudo systemctl stop NetworkManager

# Delete Connection Profiles
$ sudo find /etc/NetworkManager/system-connections/ -type f -delete    # This deletes all profiles, if you have other profiles for Wi-Fi, etc., narrow your delete range

# Delete the persistent lease files in the Workstation
$ sudo find /var/lib/NetworkManager/ -name "*.lease" -delete    # Same, this deletes all leases
```

Before restarting NetworkManager, open a second terminal tab and use ```tcpdump``` so that the frames can be captured.
```bash
# Port 67 for the DHCP server, Port 68 for the DHCP client
$ sudo tcpdump -i enp7s0f1u3u4 port 67 or port 68 -env
tcpdump: listening on enp7s0f1u3u4, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Return to the first terminal and restart NetworkManager.
```bash
# Restart NetworkManager to force a pure DHCPDISCOVER
$ sudo systemctl start NetworkManager
```

Then look at the frames captured by ```tcpdump```.
```bash
14:22:39.306461 [Router MAC] > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342: (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto UDP (17), length 328)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from [Router MAC], length 300, xid 0x18dfdab1, Flags [none]
	  Client-Ethernet-Address [Router MAC]
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Discover
	    MSZ (57), length 2: 576
	    Parameter-Request (55), length 7: 
	      Subnet-Mask (1), Default-Gateway (3), Domain-Name-Server (6), Hostname (12)
	      Domain-Name (15), BR (28), NTP (42)
	    Vendor-Class (60), length 12: "udhcp 1.36.1"
	    Client-ID (61), length 7: ether [Router MAC]
	    
14:22:43.671920 [USB-to-Ethernet Adapter MAC] > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 318: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto UDP (17), length 304)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from [USB-to-Ethernet Adapter MAC], length 276, xid 0x787404e9, secs 7, Flags [none]
	  Client-Ethernet-Address [USB-to-Ethernet Adapter MAC]
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Discover
	    Client-ID (61), length 7: ether [USB-to-Ethernet Adapter MAC]
	    Parameter-Request (55), length 17: 
	      Subnet-Mask (1), Time-Zone (2), Domain-Name-Server (6), Hostname (12)
	      Domain-Name (15), MTU (26), BR (28), Classless-Static-Route (121)
	      Default-Gateway (3), Static-Route (33), YD (40), YS (41)
	      NTP (42), Unknown (119), Classless-Static-Route-Microsoft (249), Unknown (252)
	      RP (17)
	    MSZ (57), length 2: 576
	    
14:22:43.685745 [Router MAC] > [USB-to-Ethernet Adapter MAC], ethertype IPv4 (0x0800), length 357: (tos 0xc0, ttl 64, id 3137, offset 0, flags [none], proto UDP (17), length 343)
    192.168.1.1.67 > 192.168.1.181.68: BOOTP/DHCP, Reply, length 315, xid 0x787404e9, secs 7, Flags [none]
	  Your-IP 192.168.1.181
	  Server-IP 192.168.1.1
	  Client-Ethernet-Address [USB-to-Ethernet Adapter MAC]
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Offer
	    Server-ID (54), length 4: 192.168.1.1
	    Lease-Time (51), length 4: 43200
	    RN (58), length 4: 21600
	    RB (59), length 4: 37800
	    Subnet-Mask (1), length 4: 255.255.255.0
	    BR (28), length 4: 192.168.1.255
	    Default-Gateway (3), length 4: 192.168.1.1
	    Domain-Name-Server (6), length 4: 192.168.1.1
	    Domain-Name (15), length 3: "lan"
	    Hostname (12), length 16: "workstation-arch"
	    
14:22:43.685825 [USB-to-Ethernet Adapter MAC] > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 330: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto UDP (17), length 316)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from [USB-to-Ethernet Adapter MAC], length 288, xid 0x787404e9, secs 7, Flags [none]
	  Client-Ethernet-Address [USB-to-Ethernet Adapter MAC]
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Request
	    Client-ID (61), length 7: ether [USB-to-Ethernet Adapter MAC]
	    Parameter-Request (55), length 17: 
	      Subnet-Mask (1), Time-Zone (2), Domain-Name-Server (6), Hostname (12)
	      Domain-Name (15), MTU (26), BR (28), Classless-Static-Route (121)
	      Default-Gateway (3), Static-Route (33), YD (40), YS (41)
	      NTP (42), Unknown (119), Classless-Static-Route-Microsoft (249), Unknown (252)
	      RP (17)
	    MSZ (57), length 2: 576
	    Requested-IP (50), length 4: 192.168.1.181
	    Server-ID (54), length 4: 192.168.1.1
	    
14:22:43.701104 [Router MAC] > [USB-to-Ethernet Adapter MAC], ethertype IPv4 (0x0800), length 357: (tos 0xc0, ttl 64, id 3138, offset 0, flags [none], proto UDP (17), length 343)
    192.168.1.1.67 > 192.168.1.181.68: BOOTP/DHCP, Reply, length 315, xid 0x787404e9, secs 7, Flags [none]
	  Your-IP 192.168.1.181
	  Server-IP 192.168.1.1
	  Client-Ethernet-Address [USB-to-Ethernet Adapter MAC]
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: ACK
	    Server-ID (54), length 4: 192.168.1.1
	    Lease-Time (51), length 4: 43200
	    RN (58), length 4: 21600
	    RB (59), length 4: 37800
	    Subnet-Mask (1), length 4: 255.255.255.0
	    BR (28), length 4: 192.168.1.255
	    Default-Gateway (3), length 4: 192.168.1.1
	    Domain-Name-Server (6), length 4: 192.168.1.1
	    Domain-Name (15), length 3: "lan"
	    Hostname (12), length 16: "workstation-arch"
```

The first frame is the Router initiating DORA with the upstream network. Only the Discovery was caught because only Discover and Request are broadcast frames, and by the time the Request frame came back, the Router likely contained the WAN interface. The next four frames each represent each of the DORA sequence between the Workstation and the Router.

```bash
# Confirm that Static IP allocation is happening due to Router settings and not Client-side cache
$ ip -4 a show dev enp7s0f1u3u4
5: enp7s0f1u3u4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.1.181/24 brd 192.168.1.255 scope global dynamic noprefixroute enp7s0f1u3u4
       valid_lft 42182sec preferred_lft 42182sec
```

#### Prepare files PXE Provisioning Server on Workstation
```bash
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

# Download vanilla iPXE bootloader from the official source
$ sudo curl -o /srv/tftp/ipxe-arch.efi https://boot.ipxe.org/x86_64-efi/ipxe.efi

# Modify permissions so that TFTP daemon can read the file
$ sudo chmod 644 /srv/tftp/ipxe-arch.efi
```

#### Write custom iPXE file on Workstation
```bash
$ sudo tee /srv/http/provision/boot.ipxe > /dev/null << 'EOF'
#!ipxe
echo =========================================
echo Arch Linux Provisioning Service v1.0
echo =========================================

# Ensure the interface is fully initialized
dhcp

# Set the base URL variable for your Workstation
set srv http://192.168.1.181/provision

# Load the kernel and inject the local HTTP hooks and automation script
kernel ${srv}/vmlinuz-linux ip=dhcp archisobasedir=arch archiso_http_srv=${srv}/ script=${srv}/autoinstall.sh
initrd ${srv}/initramfs-linux.img

# Execute
boot
EOF
```

#### Write custom installation script on Workstation

```bash

```

#### Start the Provisioning Servers on Workstation
```bash
# Edit TFTP IP
$ sudo bash -c 'echo "TFTPD_ARGS=\"--verbose --user nobody --address 192.168.1.181:69 --secure /srv/tftp\"" > /etc/conf.d/tftpd'

# Start TFTP
$ sudo systemctl start tftpd.service

# Confirm that TFTP is listening on 192.168.1.181:69
$ ss -uln | grep 192.168.1.181:69
UNCONN 0      0                                 192.168.1.181:69         0.0.0.0:*

# Start HTTP
$ sudo python3 -m http.server 80 --directory /srv/http/provision
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Configure Router to direct Laptop to Workstation Servers
```bash
$ ssh openwrt
# Tag DHCP Broadcasts that include iPXE in their headers as 'ipxe'
root@OpenWrt:~# uci add_list dhcp.@dnsmasq[0].dhcp_userclass='set:ipxe,iPXE'
# If not 'ipxe', direct to TFTP
root@OpenWrt:~# uci add_list dhcp.@dnsmasq[0].dhcp_boot='tag:!ipxe,ipxe.efi,192.168.1.181,192
.168.1.181'
# If 'ipxe', direct to iPXE
root@OpenWrt:~# uci add_list dhcp.@dnsmasq[0].dhcp_boot='tag:ipxe,http://192.168.1.181/provis
ion/boot.ipxe,192.168.1.181,192.168.1.181'
root@OpenWrt:~# uci commit dhcp
root@OpenWrt:~# /etc/init.d/dnsmasq restart

# Confirm that the setting was applied
root@OpenWrt:~# cat /var/etc/dnsmasq.conf.cfg* | grep dhcp-boot
dhcp-boot=tag:!ipxe,ipxe.efi,192.168.1.181,192.168.1.181 tag:ipxe,http://192.168.1.181/provision/boot.ipxe,192.168.1.181,192.168.1.181
root@OpenWrt:~# exit
```

### Provision Laptop
Go to your laptop and power it on. Repeatedly press the Fx keys as soon as the laptop starts booting. Disable Secure Boot (Since iPXE is not signed by Microsoft), enable Network Boot, and select PXE Boot.

```bash

```

Day 2 took significantly longer than I thought. PXE was quite fragile and I learned a lot while troubleshooting. Read a lot of tcpdump output to diagnose what exactly was going wrong. On Day 3 I will finish the autoinstall.sh script and automatically provision my Laptop with Arch Linux. I will then write an Ansible playbook that does the rest of the configuration, completing the interventionless workflow.