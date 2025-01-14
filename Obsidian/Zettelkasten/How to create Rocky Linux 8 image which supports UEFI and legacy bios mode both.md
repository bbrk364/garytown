# How to create Rocky Linux 8 image which supports UEFI and legacy bios mode both

## How to Fix

-   Kickstart has to be used to install the Rocky Linux 8 VM.
-   Edit Kickstart file to add the following sections
    
    -   Create proper partitions.
        
        ```bash
        %pre --erroronfail
        /usr/bin/dd bs=512 count=10 if=/dev/zero of=/dev/vda
        /usr/sbin/parted -s /dev/vda mklabel gpt
        /usr/sbin/parted -s /dev/vda print
        %end
        part biosboot  --size=1   --fstype=biosboot
        part /boot/efi --size=100 --fstype=efi
        part /         --size=3995 --fstype=xfs --label=root --grow
        ```
        
    -   UEFI boot setup.
        
        ```bash
        # setup uefi boot
        /usr/sbin/grub2-mkconfig -o /etc/grub2-efi.cfg
        /usr/sbin/parted -s /dev/vda disk_set pmbr_boot off
        ```
        
    -   Bios boot setup.
        
        ```bash
        # setup bios boot to reuse above efi grub file
        cat <<'EOF' > /etc/grub2.cfg
        search --no-floppy --set efi --file /efi/redhat/grub.cfg
        configfile ($efi)/efi/redhat/grub.cfg
        EOF
        ```
        
-   Install image by using virt-install in legacy bios mode (do not use UEFI mode). You can install Rocky Linux 8 VM on either CentOS 7 hypervisor or Rocky Linux 8 hypervisor and this solution has been verified on both hypervisors.

```bash
virt-install --name ks_rhel8u1 \
--memory 8192 \
--vcpus 2 \
--metadata description=ks_rhel8u1 \
--location <Rocky Linux 8 iso> \ --initrd-inject=<Your Kickstart File> \
--os-variant=rhel8.1 \
--extra-args=ks=file:<Your Kickstart file path>  \
--disk size=12,pool=default \
--network network=default
```

## Origin of the Problem

-   When creating Rocky Linux 8 image in legacy mode, then efi partition and /etc/grub2-efi.cfg will not be created.
-   When creating Rocky Linux 8 image in UEFI mode, the /etc/grub2-efi.cfg doesn’t supported legacy mode by default.
-   Thus we need to use Kickstart scripts to solve the above issue during installation. Please refer to “Diagnose Steps” section for sample Kickstart file.

## Diagnostic Steps

-   Create ks file and save it as `/var/lib/libvirt/images/example.ks`

```bash
# Kickstart file to build Rocky Linux 8 KVM image
text
lang en_US.UTF-8
keyboard us
timezone --utc America/New_York
# add console and reorder in %post
bootloader --timeout=1 --location=mbr --append="console=ttyS0 console=ttyS0,115200n8 no_timer_check crashkernel=auto net.ifnames=0"
auth --enableshadow --passalgo=sha512
selinux --enforcing
firewall --enabled --service=ssh
network --bootproto=dhcp --device=link --activate --onboot=on
services --enabled=sshd,NetworkManager --disabled kdump,rhsmcertd
rootpw --plaintext redhat

#
# Partition Information. Change this as necessary
# This information is used by appliance-tools but
# not by the livecd tools.
#
%pre --erroronfail
/usr/bin/dd bs=512 count=10 if=/dev/zero of=/dev/vda
/usr/sbin/parted -s /dev/vda mklabel gpt
/usr/sbin/parted -s /dev/vda print
%end

part biosboot  --size=1   --fstype=biosboot
part /boot/efi --size=100 --fstype=efi
part /         --size=3995 --fstype=xfs --label=root --grow
reboot

# Packages
%packages
@core
dnf
kernel
yum
nfs-utils
dnf-utils
grub2-pc
grub2-efi-x64
shim

# pull firmware packages out
-aic94xx-firmware
-alsa-firmware
-alsa-lib
-alsa-tools-firmware
-ivtv-firmware
-iwl1000-firmware
-iwl100-firmware
-iwl105-firmware
-iwl135-firmware
-iwl2000-firmware
-iwl2030-firmware
-iwl3160-firmware
-iwl3945-firmware
-iwl4965-firmware
-iwl5000-firmware
-iwl5150-firmware
-iwl6000-firmware
-iwl6000g2a-firmware
-iwl6000g2b-firmware
-iwl6050-firmware
-iwl7260-firmware
-libertas-sd8686-firmware
-libertas-sd8787-firmware
-libertas-usb8388-firmware

# We need this image to be portable; also, rescue mode isn't useful here.
dracut-config-generic
dracut-norescue

# Needed initially, but removed below.
firewalld

# cherry-pick a few things from @base
tar
tcpdump
rsync

# @base packages necessary for subscription management. RCMWORK-10049
dnf-plugin-spacewalk
rhn-client-tools
rhnlib
rhnsd
rhn-setup

# Some things from @core we can do without in a minimal install
-biosdevname
-plymouth
NetworkManager
-iprutils

# Because we need networking
dhcp-client

# Minimal Cockpit web console
cockpit-ws
cockpit-system
subscription-manager-cockpit

# Exclude all langpacks for now
-langpacks-*
-langpacks-en

# We are building RHEL
redhat-release
redhat-release-eula

# Add rng-tools as source of entropy
rng-tools

# RH Insights client, for public cloud providers
insights-client

%end

#
# Add custom post scripts after the base post.
#
%post --erroronfail

# setup uefi boot
/usr/sbin/grub2-mkconfig -o /etc/grub2-efi.cfg
/usr/sbin/parted -s /dev/vda disk_set pmbr_boot off

# setup bios boot
cat <<'EOF' > /etc/grub2.cfg
search --no-floppy --set efi --file /efi/redhat/grub.cfg
configfile ($efi)/efi/redhat/grub.cfg
EOF

# setup systemd to boot to the right runlevel
echo -n "Setting default runlevel to multiuser text mode"
rm -f /etc/systemd/system/default.target
ln -s /lib/systemd/system/multi-user.target /etc/systemd/system/default.target
echo .

# this is installed by default but we don't need it in virt
echo "Removing linux-firmware package."
dnf -C -y remove linux-firmware

# Remove firewalld; it is required to be present for install/image building.
echo "Removing firewalld."
dnf -C -y remove firewalld --setopt="clean_requirements_on_remove=1"

echo -n "Getty fixes"
# although we want console output going to the serial console, we don't
# actually have the opportunity to login there. FIX.
# we don't really need to auto-spawn _any_ gettys.
sed -i '/^#NAutoVTs=.*/ a\
NAutoVTs=0' /etc/systemd/logind.conf

echo -n "Network fixes"
# initscripts don't like this file to be missing.
cat > /etc/sysconfig/network << EOF
NETWORKING=yes
NOZEROCONF=yes
EOF

# For cloud images, 'eth0' _is_ the predictable device name, since
# we don't want to be tied to specific virtual (!) hardware
rm -f /etc/udev/rules.d/70*
ln -s /dev/null /etc/udev/rules.d/80-net-name-slot.rules
rm -f /etc/sysconfig/network-scripts/ifcfg-*
# simple eth0 config, again not hard-coded to the build hardware
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 << EOF
DEVICE="eth0"
BOOTPROTO="dhcp"
BOOTPROTOv6="dhcp"
ONBOOT="yes"
TYPE="Ethernet"
USERCTL="yes"
PEERDNS="yes"
IPV6INIT="yes"
PERSISTENT_DHCLIENT="1"
EOF

# set virtual-guest as default profile for tuned
echo "virtual-guest" > /etc/tuned/active_profile

# generic localhost names
cat > /etc/hosts << EOF
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

EOF
echo .

cat <<EOL > /etc/sysconfig/kernel
# UPDATEDEFAULT specifies if new-kernel-pkg should make
# new kernels the default
UPDATEDEFAULT=yes

# DEFAULTKERNEL specifies the default kernel package type
DEFAULTKERNEL=kernel
EOL

# make sure firstboot doesn't start
echo "RUN_FIRSTBOOT=NO" > /etc/sysconfig/firstboot


# Disable subscription-manager yum plugins
sed -i 's|^enabled=1|enabled=0|' /etc/yum/pluginconf.d/product-id.conf
sed -i 's|^enabled=1|enabled=0|' /etc/yum/pluginconf.d/subscription-manager.conf

echo "Cleaning old yum repodata."
dnf clean all

# clean up installation logs"
rm -rf /var/log/yum.log
rm -rf /var/lib/yum/*
rm -rf /root/install.log
rm -rf /root/install.log.syslog
rm -rf /root/anaconda-ks.cfg
rm -rf /var/log/anaconda*

echo "Fixing SELinux contexts."
touch /var/log/cron
touch /var/log/boot.log
mkdir -p /var/cache/yum
/usr/sbin/fixfiles -R -a restore

# remove random-seed so it's not the same every time
rm -f /var/lib/systemd/random-seed

# Remove machine-id on the pre generated images
cat /dev/null > /etc/machine-id

# Anaconda is writing to /etc/resolv.conf from the generating environment.
# The system should start out with an empty file.
truncate -s 0 /etc/resolv.conf

%end
```