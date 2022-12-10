ESXi (vSphere) and virtualisation in general is a great way to fully utilise server resources, reduce power costs and improve disaster recovery times.  In fact over 80% of all all businesses have adopted virtualisation in some way or form.  Its the way of the future.

But loading on a virtualisation hypervisor (in our example Vmware vSphere) is all well and good, but it provides an abstraction layer that can hinder traditional software management functions like array management/diagnosis and hardware status polling.

so how do you enhance your virtualisation hypervisor?

**Installing HP tools on esxi hosts  (array management and enhanced CIM monitoring)**

The below example is for ESXi version 5 and 5.1.  If you are running version 5.5 then  go to the HP vibsdepot for other versions ([http://vibsdepot.hp.com/hpq/](http://vibsdepot.hp.com/hpq/ "http://vibsdepot.hp.com/hpq/"))

to start you need to first enable SSH on your ESXi server.  Just go to vSphere management tool –> configuration tab –> security profile –> services properties , and set SSH to start

[![image](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/07/image_thumb1.png "image")](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/07/image1.png)

Now that SSH is running open putty and ssh into the host logging in with a root account or similar

Are the HP tools already installed?

esxcli software vib list | grep hp

if the above command doesn’t return anything then do the following to perform the install (just copy and past the text)

cd /tmp/

wget [http://vibsdepot.hp.com/hpq/feb2014/esxi-5x-bundles/hp-esxi5.0uX-bundle-1.6-20.zip](http://vibsdepot.hp.com/hpq/feb2014/esxi-5x-bundles/hp-esxi5.0uX-bundle-1.6-20.zip)

wget [http://vibsdepot.hp.com/hpq/feb2014/esxi-5x-bundles/hp-ams-esxi5.0-bundle-9.5.0-15.zip](http://vibsdepot.hp.com/hpq/feb2014/esxi-5x-bundles/hp-ams-esxi5.0-bundle-9.5.0-15.zip)

esxcli software vib install -d /tmp/hp-esxi5.0uX-bundle-1.6-20.zip

esxcli software vib install -d /tmp/hp-ams-esxi5.0-bundle-9.5.0-15.zip

Now you are done, reboot the server to apply the chances

after its rebooted you can run commands like the below to see how many disks are in the server and which disks have failed etc

/opt/hp/hpacucli/bin/hpacucli

=> ctrl all show config

Smart Array P410 in Slot 1                (sn: PACCRID11330V3R)

   array A (SAS, Unused Space: 0  MB)

      logicaldrive 1 (279.4 GB, RAID 1, OK)

      physicaldrive 1I:1:1 (port 1I:box 1:bay 1, SAS, 300 GB, OK)

      physicaldrive 1I:1:2 (port 1I:box 1:bay 2, SAS, 300 GB, OK)

   array B (SAS, Unused Space: 0  MB)

      logicaldrive 2 (1.6 TB, RAID 5, Failed)

      physicaldrive 1I:1:3 (port 1I:box 1:bay 3, SAS, 600 GB, OK)

      physicaldrive 1I:1:4 (port 1I:box 1:bay 4, SAS, 600 GB, OK)

      physicaldrive 1I:1:5 (port 1I:box 1:bay 5, SAS, 600 GB, Failed)

      physicaldrive 1I:1:6 (port 1I:box 1:bay 6, SAS, 600 GB, Failed)

      physicaldrive 1I:1:7 (port 1I:box 1:bay 7, SAS, 600 GB, Failed, spare)

   Expander 250 (WWID: 500E004AAAAAAA3F, Port: 1I, Box: 1)