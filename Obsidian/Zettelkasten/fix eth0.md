#Fixing the interface to eth0 Centos 7 :

sed -i -e 's/quiet/quiet net.ifnames=0 biosdevname=0/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

#The above command adds a few arguments to the kernel args list (namely net.ifnames=0 and biosdevname=0. It may be useful to view the /etc/default/grub file and ensure these settings were indeed applied.
#The next step is to adjust the network-scripts in centOS. we need to ensure we have a file called /etc/sysconfig/network-scripts/ifcfg-eth0#
Below is a script that we run on our packer builds to prepare the machines network configuration files.

export iface_file=$(basename "$(find /etc/sysconfig/network-scripts/ -name 'ifcfg*' -not -name 'ifcfg-lo' | head -n 1)")
export iface_name=${iface_file:6}
echo $iface_file
echo $iface_name
	mv /etc/sysconfig/network-scripts/$iface_file /etc/sysconfig/network-scripts/ifcfg-eth0
	sed -i -e "s/$iface_name/eth0/" /etc/sysconfig/network-scripts/ifcfg-eth0
	bash -c 'echo NM_CONTROLLED=\"no\" >> /etc/sysconfig/network-scripts/ifcfg-eth0'




#	
	C			entos 8:

    sed -i -e 's/quiet/quiet net.ifnames=0 biosdevname=0/' /etc/default/grub

    grub2-mkconfig -o /boot/grub2/grub.cfg #(location may be different, could be located at /boot/efi/EFI/centos/grub.cfg)

    ifdown <orginal-nic>

    mv /etc/sysconfig/network-scripts/<orginal-nic>  /etc/sysconfig/network-scripts/ifcfg-eth0 (this changes name/device to eth0)

    Edit ifcfg-eth0 and change the NAME to eth0

    bash -c 'echo NM_CONTROLLED=\"no\" >> /etc/sysconfig/network-scripts/ifcfg-eth0'

    ip link set <orginal-nic> down

    ip link set <orginal-nic> name eth0

    ip link set eth0 up

    ifup eth0
