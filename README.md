# cloudflare_ai_routing
Custom routing solution which utilizes Workers AI of Cloudflare for Students.

## Day 1: Router & Workstation Setup
To have full control of the router, we replace the stock firmware with a open source firmware. I chose [OpenWRT](https://openwrt.org/). I used the [TP-Link Archer C7 AC1750 v5](https://www.tp-link.com/us/home-networking/wifi-router/archer-c7/). I prepared an Arch Linux Workstation which is used to configure the router.

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

Connect Router to Internet if you haven't already

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