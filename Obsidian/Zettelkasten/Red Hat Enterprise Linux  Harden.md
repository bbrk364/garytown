 Red Hat and Red Hat Enterprise Linux are either registered trademarks or trademarks of Red Hat, Inc. in the United States and other countries. All other names are registered trademarks or trademarks of their respective companies. 0.9 PCI-DSS v3 Control Baseline for Red Hat Enterprise Linux 7 This is a *draft* profile for PCI-DSS v3 Red Hat Corporate Profile for Certified Cloud Providers (RH CCP) This is a *draft* SCAP profile for Red Hat Certified Cloud Providers Common Profile for General-Purpose Systems This profile contains items common to general-purpose desktop and server installations. Pre-release Draft STIG for RHEL 7 Server This profile is being developed under the DoD consensus model to become a STIG in coordination with DISA FSO. A conditional clause for check statements. A conditional clause for check statements. This is a placeholder. Introduction The purpose of this guidance is to provide security configuration recommendations and baselines for the Red Hat Enterprise Linux (RHEL) 7 operating system. The guidance provided here should be applicable to all variants (Desktop, Server, Advanced Platform) of the product. Recommended settings for the basic operating system are provided, as well as for many network services that the system can provide to other systems. The guide is intended for system administrators. Readers are assumed to possess basic system administration skills for Unix-like systems, as well as some familiarity with Red Hat's documentation and administration conventions. Some instructions within this guide are complex. All directions should be followed completely and with understanding of their effects in order to avoid serious adverse effects on the system and its security. General Principles The following general principles motivate much of the advice in this guide and should also influence any configuration decisions that are not explicitly covered. Encrypt Transmitted Data Whenever Possible Data transmitted over a network, whether wired or wireless, is susceptible to passive monitoring. Whenever practical solutions for encrypting such data exist, they should be applied. Even if data is expected to be transmitted only over a local network, it should still be encrypted. Encrypting authentication data, such as passwords, is particularly important. Networks of RHEL 7 machines can and should be configured so that no unencrypted authentication data is ever transmitted between machines. Minimize Software to Minimize Vulnerability The simplest way to avoid vulnerabilities in software is to avoid installing that software. On RHEL, the RPM Package Manager (originally Red Hat Package Manager, abbreviated RPM) allows for careful management of the set of software packages installed on a system. Installed software contributes to system vulnerability in several ways. Packages that include setuid programs may provide local attackers a potential path to privilege escalation. Packages that include network services may give this opportunity to network-based attackers. Packages that include programs which are predictably executed by local users (e.g. after graphical login) may provide opportunities for trojan horses or other attack code to be run undetected. The number of software packages installed on a system can almost always be significantly pruned to include only the software for which there is an environmental or operational need. Run Different Network Services on Separate Systems Whenever possible, a server should be dedicated to serving exactly one network service. This limits the number of other services that can be compromised in the event that an attacker is able to successfully exploit a software flaw in one network service. Configure Security Tools to Improve System Robustness Several tools exist which can be effectively used to improve a system's resistance to and detection of unknown attacks. These tools can improve robustness against attack at the cost of relatively little configuration effort. In particular, this guide recommends and discusses the use of Iptables for host-based firewalling, SELinux for protection against vulnerable services, and a logging and auditing infrastructure for detection of problems. Least Privilege Grant the least privilege necessary for user accounts and software to perform tasks. For example, sudo can be implemented to limit authorization to super user accounts on the system only to designated personnel. Another example is to limit logins on server systems to only those administrators who need to log into them in order to perform administration tasks. Using SELinux also follows the principle of least privilege: SELinux policy can confine software to perform only actions on the system that are specifically allowed. This can be far more restrictive than the actions permissible by the traditional Unix permissions model. How to Use This Guide Readers should heed the following points when using the guide. Read Sections Completely and in Order Each section may build on information and recommendations discussed in prior sections. Each section should be read and understood completely; instructions should never be blindly applied. Relevant discussion may occur after instructions for an action. Test in Non-Production Environment This guidance should always be tested in a non-production environment before deployment. This test environment should simulate the setup in which the system will be deployed as closely as possible. Root Shell Environment Assumed Most of the actions listed in this document are written with the assumption that they will be executed by the root user running the /bin/bash shell. Commands preceded with a hash mark (#) assume that the administrator will execute the commands as root, i.e. apply the command via sudo whenever possible, or use su to gain root privileges if sudo cannot be used. Commands which can be executed as a non-root user are are preceded by a dollar sign ($) prompt. Formatting Conventions Commands intended for shell execution, as well as configuration file text, are featured in a monospace font. Italics are used to indicate instances where the system administrator must substitute the appropriate information into a command or configuration file. Reboot Required A system reboot is implicitly required after some actions in order to complete the reconfiguration of the system. In many cases, the changes will not take effect until a reboot is performed. In order to ensure that changes are applied properly and to test functionality, always reboot the system after applying a set of recommendations from this guide. System Settings Installing and Maintaining Software The following sections contain information on security-relevant choices during the initial operating system installation process and the setup of software updates. Disk Partitioning To ensure separation and protection of data, there are top-level system directories which should be placed on their own physical partition or logical volume. The installer's default partitioning scheme creates separate logical volumes for /, /boot, and swap.

    If starting with any of the default layouts, check the box to "Review and modify partitioning." This allows for the easy creation of additional logical volumes inside the volume group already created, though it may require making /'s logical volume smaller to create space. In general, using logical volumes is preferable to using partitions because they can be more easily adjusted later.
    If creating a custom layout, create the partitions mentioned in the previous paragraph (which the installer will require anyway), as well as separate ones described in the following sections.

If a system has already been installed, and the default partitioning scheme was used, it is possible but nontrivial to modify it to create separate logical volumes for the directories listed above. The Logical Volume Manager (LVM) makes this possible. See the LVM HOWTO at http://tldp.org/HOWTO/LVM-HOWTO/ for more detailed information on LVM. Ensure /tmp Located On Separate Partition The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM. Test attestation on 20120928 by MM The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it. CCE-27173-4 Run the following command to determine if /tmp is on its own partition or logical volume:

$ mount | grep "on /tmp "

If /tmp has its own partition or volume group, a line will be returned. Ensure /var Located On Separate Partition The /var directory is used by daemons and other system services to store frequently-changing data. Ensure that /var has its own partition or logical volume at installation time, or migrate it using LVM. Test attestation on 20120928 by MM Ensuring that /var is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the /var directory to contain world-writable directories installed by other software packages. CCE-26404-4 Run the following command to determine if /var is on its own partition or logical volume:

$ mount | grep "on /var "

If /var has its own partition or volume group, a line will be returned. Ensure /var/log Located On Separate Partition System logs are stored in the /var/log directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM. AU-9 Test attestation on 20120928 by MM Placing /var/log in its own partition enables better separation between log files and other files in /var/. CCE-26967-0 Run the following command to determine if /var/log is on its own partition or logical volume:

$ mount | grep "on /var/log "

If /var/log has its own partition or volume group, a line will be returned. Ensure /var/log/audit Located On Separate Partition Audit logs are stored in the /var/log/audit directory. Ensure that it has its own partition or logical volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to store all audit logs that will be created by the auditing daemon. AU-4 AU-9 Test attestation on 20120928 by MM Placing /var/log/audit in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space. CCE-26971-2 Run the following command to determine if /var/log/audit is on its own partition or logical volume:

$ mount | grep "on /var/log/audit "

If /var/log/audit has its own partition or volume group, a line will be returned. Ensure /home Located On Separate Partition If user home directories will be stored locally, create a separate partition for /home at installation time (or migrate it later using LVM). If /home will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later. 1208 Test attestation on 20120928 by MM Ensuring that /home is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage. CCE-RHEL7-CCE-TBD Run the following command to determine if /home is on its own partition or logical volume:

$ mount | grep "on /home "

If /home has its own partition or volume group, a line will be returned. Encrypt Partitions Red Hat Enterprise Linux 7 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time.

For manual installations, select the Encrypt checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots.

For automated/unattended installations, it is possible to use Kickstart by adding the --encrypted and --passphrase= options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition:

part / --fstype=ext4 --size=100 --onpart=hda1 --encrypted --passphrase=PASSPHRASE

Any PASSPHRASE is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the --passphrase= option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation.

Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:
https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Encryption.html SC-13 SC-28 1019 1199 1200 185 The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost. CCE-27128-8 Determine if encryption must be used to protect data on the system. Updating Software The yum command line tool is used to install and update software packages. The system also provides a graphical software update tool in the System menu, in the Administration submenu, called Software Update.

Red Hat Enterprise Linux systems contain an installed software catalog called the RPM database, which records metadata of installed packages. Consistently using yum or the graphical Software Update for all software installation allows for insight into the current inventory of installed software on the system. Ensure Red Hat GPG Key Installed To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them), the Red Hat GPG key must properly be installed. To install the Red Hat GPG key, run:

$ sudo rhn_register

If the system is not connected to the Internet or an RHN Satellite, then install the Red Hat GPG key from trusted media such as the Red Hat installation CD-ROM or DVD. Assuming the disc is mounted in /media/cdrom, use the following command as the root user to import it into the keyring:

$ sudo rpm --import /media/cdrom/RPM-GPG-KEY

CM-5(3) SI-7 MA-1(b) 1749 366 Test attestation on 20150407 by sdw Changes to software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor. The Red Hat GPG key is necessary to cryptographically verify packages are from Red Hat. CCE-26957-1 # The two fingerprints below are retrieved from https://access.redhat.com/security/team/key readonly REDHAT_RELEASE_2_FINGERPRINT="567E 347A D004 4ADE 55BA 8A5F 199E 2F91 FD43 1D51" readonly REDHAT_AUXILIARY_FINGERPRINT="43A6 E49C 4A38 F4BE 9ABF 2A53 4568 9C88 2FA6 58E0" # Location of the key we would like to import (once it's integrity verified) readonly REDHAT_RELEASE_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" RPM_GPG_DIR_PERMS=$(stat -c %a "$(dirname "$REDHAT_RELEASE_KEY")") # Verify /etc/pki/rpm-gpg directory permissions are safe if [ "${RPM_GPG_DIR_PERMS}" -le "755" ] then # If they are safe, try to obtain fingerprints from the key file # (to ensure there won't be e.g. CRC error) IFS=$'\n' GPG_OUT=($(gpg --with-fingerprint "${REDHAT_RELEASE_KEY}")) GPG_RESULT=$? # No CRC error, safe to proceed if [ "${GPG_RESULT}" -eq "0" ] then for ITEM in "${GPG_OUT[@]}" do # Filter just hexadecimal fingerprints from gpg's output from # processing of a key file RESULT=$(echo ${ITEM} | sed -n "s/[[:space:]]*Key fingerprint = \(.*\)/\1/p" | tr -s '[:space:]') # If fingerprint matches Red Hat's release 2 or auxiliary key import the key if [[ ${RESULT} ]] && ([[ ${RESULT} = "${REDHAT_RELEASE_2_FINGERPRINT}" ]] || \ [[ ${RESULT} = "${REDHAT_AUXILIARY_FINGERPRINT}" ]]) then rpm --import "${REDHAT_RELEASE_KEY}" fi done fi fi To ensure that the GPG key is installed, run:

$ rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey

The command should return the string below:

gpg(Red Hat, Inc. (release key 2)  <security@redhat.com>

Ensure gpgcheck Enabled In Main Yum Configuration The gpgcheck option controls whether RPM packages' signatures are always checked prior to installation. To configure yum to check package signatures before installing them, ensure the following line appears in /etc/yum.conf in the [main] section:

gpgcheck=1

CM-5(3) SI-7 MA-1(b) 1749 366 Test attestation on 20150407 by sdw Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. Certificates used to verify the software must be from an approved Certificate Authority (CA). CCE-26989-4 To determine whether yum is configured to use gpgcheck, inspect /etc/yum.conf and ensure the following appears in the [main] section:

gpgcheck=1

A value of 1 indicates that gpgcheck is enabled. Absence of a gpgcheck line or a setting of 0 indicates that it is disabled. Ensure gpgcheck Enabled For All Yum Package Repositories To ensure signature checking is not disabled for any repos, remove any lines from files in /etc/yum.repos.d of the form:

gpgcheck=0

CM-5(3) SI-7 MA-1(b) 1749 366 Test attestation on 20150407 by sdw Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. Certificates used to verify the software must be from an approved Certificate Authority (CA). CCE-26876-3 To determine whether yum has been configured to disable gpgcheck for any repos, inspect all files in /etc/yum.repos.d and ensure the following does not appear in any sections:

gpgcheck=0

A value of 0 indicates that gpgcheck has been disabled for that repo. Ensure Software Patches Installed If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates:

$ sudo yum update

If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using rpm. SI-2 MA-1(b) Test attestation on 20120928 by MM Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities. CCE-26853-2 If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available:

$ sudo yum check-update

If the system is not configured to update from one of these sources, run the following command to list when each package was last updated:

$ rpm -qa -last

Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine if the system is missing applicable updates. Software Integrity Checking Both the AIDE (Advanced Intrusion Detection Environment) software and the RPM package management system provide mechanisms for verifying the integrity of installed software. AIDE uses snapshots of file metadata (such as hashes) and compares these to current system files in order to detect changes. The RPM package management system can conduct integrity checks by comparing information in its metadata database with files installed on the system.

Integrity checking cannot prevent intrusions, but can detect that they have occurred. Requirements for software integrity checking may be highly dependent on the environment in which the system will be used. Snapshot-based approaches such as AIDE may induce considerable overhead in the presence of frequent software updates. Verify Integrity with AIDE AIDE conducts integrity checks by comparing information about files with previously-gathered information. Ideally, the AIDE database is created immediately after initial system configuration, and then again after any software update. AIDE is highly configurable, with further configuration information located in /usr/share/doc/aide-VERSION. Install AIDE Install the AIDE package with the command:

$ sudo yum install aide

CM-3(d) CM-3(e) CM-6(d) CM-6(3) SC-28 SI-7 Test attestation on 20121024 by DS The AIDE package must be installed if it is to be available for integrity checking. CCE-26741-9 yum -y install aide Run the following command to determine if the aide package is installed:

$ rpm -q aide

Disable Prelinking The prelinking feature changes binaries in an attempt to decrease their startup time. In order to disable it, change or add the following line inside the file /etc/sysconfig/prelink:

PRELINKING=no

Next, run the following command to return binaries to a normal, non-prelinked state:

$ sudo /usr/sbin/prelink -ua

CM-6(d) CM-6(3) SC-28 SI-7 The prelinking feature can interfere with the operation of AIDE, because it changes binaries. CCE-RHEL7-CCE-TBD # # Disable prelinking altogether # if grep -q ^PRELINKING /etc/sysconfig/prelink then sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink else echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink echo "PRELINKING=no" >> /etc/sysconfig/prelink fi # # Undo previous prelink changes to binaries # /usr/sbin/prelink -ua Build and Test AIDE Database Run the following command to generate a new database:

$ sudo /usr/sbin/aide --init

By default, the database will be written to the file /var/lib/aide/aide.db.new.gz. Storing the database, the configuration file /etc/aide.conf, and the binary /usr/sbin/aide (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity. The newly-generated database can be installed as follows:

$ sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

To initiate a manual check, run the following command:

$ sudo /usr/sbin/aide --check

If this check produces any unexpected output, investigate. CM-3(d) CM-3(e) CM-6(d) CM-6(3) SC-28 SI-7 For AIDE to be effective, an initial database of "known-good" information about files must be captured and it should be able to be verified against the installed files. CCE-RHEL7-CCE-TBD To find the location of the AIDE databse file, run the following command:

$ sudo ls -l DBDIR/database_file_name

Configure Periodic Execution of AIDE To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example. CM-3(d) CM-3(e) CM-6(d) CM-6(3) SC-28 SI-7 374 416 1069 1263 1297 1589 By default, AIDE does not install itself for periodic execution. Periodically running AIDE is necessary to reveal unexpected changes in installed files. CCE-RHEL7-CCE-TBD echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab To determine that periodic AIDE execution has been scheduled, run the following command:

$ grep aide /etc/crontab

Verify Integrity with RPM The RPM package management system includes the ability to verify the integrity of installed packages by comparing the installed files with information about the files taken from the package metadata stored in the RPM database. Although an attacker could corrupt the RPM database (analogous to attacking the AIDE database as described above), this check can still reveal modification of important files. To list which files on the system differ from what is expected by the RPM database:

$ rpm -qVa

See the man page for rpm to see a complete explanation of each column. Verify and Correct File Permissions with RPM The RPM package management system can check file access permissions of installed software packages, including many that are important to system security. After locating a file with incorrect permissions, run the following command to determine which package owns it:

$ rpm -qf FILENAME

Next, run the following command to reset its permissions to the correct values:

$ sudo rpm --setperms PACKAGENAME

AC-6 CM-6(d) CM-6(3) 1493 1494 1495 Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated. CCE-RHEL7-CCE-TBD The following command will list which files on the system have permissions different from what is expected by the RPM database:

$ rpm -Va | grep '^.M'

Verify File Hashes with RPM The RPM package management system can check the hashes of installed software packages, including many that are important to system security. Run the following command to list which files on the system have hashes that differ from what is expected by the RPM database:

$ rpm -Va | grep '^..5'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file was not expected to change, investigate the cause of the change using audit logs or other means. The package can then be reinstalled to restore the file. Run the following command to determine which package owns the file:

$ rpm -qf FILENAME

The package can be reinstalled from a yum repository using the command:

$ sudo yum reinstall PACKAGENAME

Alternatively, the package can be reinstalled from trusted media using the command:

$ sudo rpm -Uvh PACKAGENAME

CM-6(d) CM-6(3) SI-7 1496 The hashes of important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system. CCE-RHEL7-CCE-TBD The following command will list which files on the system have file hashes different from what is expected by the RPM database.

$ rpm -Va | awk '$1 ~ /..5/ && $2 != "c"'

Additional Security Software Additional security software that is not provided or supported by Red Hat can be installed to provide complementary or duplicative security capabilities to those provided by the base platform. Add-on software may not be appropriate for some specialized systems. Install Intrusion Detection Software The base Red Hat platform already includes a sophisticated auditing system that can detect intruder activity, as well as SELinux, which provides host-based intrusion prevention capabilities by confining privileged programs and user sessions which may become compromised.
In DoD environments, supplemental intrusion detection tools, such as, the McAfee Host-based Security System, are available to integrate with existing infrastructure. When these supplemental tools interfere with the proper functioning of SELinux, SELinux takes precedence.
SC-7 1263 Host-based intrusion detection tools provide a system-level defense when an intruder gains access to a system or network. CCE-RHEL7-CCE-TBD Inspect the system to determine if intrusion detection software has been installed. Verify this intrusion detection software is active. Install Virus Scanning Software Install virus scanning software, which uses signatures to search for the presence of viruses on the filesystem. The McAfee VirusScan Enterprise for Linux virus scanning tool is provided for DoD systems. Ensure virus definition files are no older than 7 days, or their last release. Configure the virus scanning software to perform scans dynamically on all accessed files. If this is not possible, configure the system to scan all altered files on the system on a daily basis. If the system processes inbound SMTP mail, configure the virus scanner to scan all received mail. SC-28 SI-3 1239 1668 Virus scanning software can be used to detect if a system has been compromised by computer viruses, as well as to limit their spread to other systems. CCE-RHEL7-CCE-TBD Inspect the system for a cron job or system service which executes a virus scanning tool regularly.
To verify the McAfee VSEL system service is operational, run the following command:

$ sudo /sbin/service nails status


To check on the age of uvscan virus definition files, run the following command:

$ sudo cd /opt/NAI/LinuxShield/engine/dat
$ sudo ls -la avvscan.dat avvnames.dat avvclean.dat

File Permissions and Masks Traditional Unix security relies heavily on file and directory permissions to prevent unauthorized users from reading or modifying files to which they should not have access.

Several of the commands in this section search filesystems for files or directories with certain characteristics, and are intended to be run on every local partition on a given system. When the variable PART appears in one of the commands below, it means that the command is intended to be run repeatedly, with the name of each local partition substituted for PART in turn.

The following command prints a list of all xfs partitions on the local system, which is the default filesystem for Red Hat Enterprise Linux 7 installations:

$ mount -t xfs | awk '{print $3}'

For any systems that use a different local filesystem type, modify this command as appropriate. Restrict Partition Mount Options System partitions can be mounted with certain options that limit what files on those partitions can do. These options are set in the /etc/fstab configuration file, and can be used to make certain types of malicious behavior more difficult. Removable Partition This value is used by the checks mount_option_nodev_removable_partitions, mount_option_nodev_removable_partitions, and mount_option_nodev_removable_partitions to ensure that the correct mount options are set on partitions mounted from removable media such as CD-ROMs, USB keys, and floppy drives. This value should be modified to reflect any removable partitions that are required on the local system. /dev/cdrom Add nodev Option to Non-Root Local Partitions The nodev mount option prevents files from being interpreted as character or block devices. Legitimate character and block devices should exist only in the /dev directory on the root partition or within chroot jails built for system services. Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of any non-root local partitions. CM-7 The nodev mount option prevents files from being interpreted as character or block devices. The only legitimate location for device files is the /dev directory located on the root partition. The only exception to this is chroot jails, for which it is not advised to set nodev on these filesystems. CCE-RHEL7-CCE-TBD Add nodev Option to Removable Media Partitions The nodev mount option prevents files from being interpreted as character or block devices. Legitimate character and block devices should exist only in the /dev directory on the root partition or within chroot jails built for system services. Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of any removable media partitions. AC-19(a) AC-19(d) AC-19(e) CM-7 MP-2 The only legitimate location for device files is the /dev directory located on the root partition. An exception to this is chroot jails, and it is not advised to set nodev on partitions which contain their root filesystems. CCE-RHEL7-CCE-TBD Add noexec Option to Removable Media Partitions The noexec mount option prevents the direct execution of binaries on the mounted filesystem. Preventing the direct execution of binaries from removable media (such as a USB key) provides a defense against malicious software that may be present on such untrusted media. Add the noexec option to the fourth column of /etc/fstab for the line which controls mounting of any removable media partitions. AC-19(a) AC-19(d) AC-19(e) CM-7 MP-2 87 Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise. CCE-RHEL7-CCE-TBD To verify that binaries cannot be directly executed from removable media, run the following command:

$ grep -v noexec /etc/fstab

The resulting output will show partitions which do not have the noexec flag. Verify all partitions in the output are not removable media. Add nosuid Option to Removable Media Partitions The nosuid mount option prevents set-user-identifier (SUID) and set-group-identifier (SGID) permissions from taking effect. These permissions allow users to execute binaries with the same permissions as the owner and group of the file respectively. Users should not be allowed to introduce SUID and SGID files into the system via partitions mounted from removeable media. Add the nosuid option to the fourth column of /etc/fstab for the line which controls mounting of any removable media partitions. AC-19(a) AC-19(d) AC-19(e) CM-7 MP-2 The presence of SUID and SGID executables should be tightly controlled. Allowing users to introduce SUID or SGID binaries from partitions mounted off of removable media would allow them to introduce their own highly-privileged programs. CCE-RHEL7-CCE-TBD Add nodev Option to /tmp The nodev mount option can be used to prevent device files from being created in /tmp. Legitimate character and block devices should not exist within temporary directories like /tmp. Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of /tmp. CM-7 MP-2 The only legitimate location for device files is the /dev directory located on the root partition. The only exception to this is chroot jails. CCE-RHEL7-CCE-TBD Add noexec Option to /tmp The noexec mount option can be used to prevent binaries from being executed out of /tmp. Add the noexec option to the fourth column of /etc/fstab for the line which controls mounting of /tmp. CM-7 MP-2 Allowing users to execute binaries from world-writable directories such as /tmp should never be necessary in normal operation and can expose the system to potential compromise. CCE-RHEL7-CCE-TBD Add nosuid Option to /tmp The nosuid mount option can be used to prevent execution of setuid programs in /tmp. The SUID and SGID permissions should not be required in these world-writable directories. Add the nosuid option to the fourth column of /etc/fstab for the line which controls mounting of /tmp. CM-7 MP-2 The presence of SUID and SGID executables should be tightly controlled. Users should not be able to execute SUID or SGID binaries from temporary storage partitions. CCE-RHEL7-CCE-TBD Add nodev Option to /dev/shm The nodev mount option can be used to prevent creation of device files in /dev/shm. Legitimate character and block devices should not exist within temporary directories like /dev/shm. Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of /dev/shm. CM-7 MP-2 The only legitimate location for device files is the /dev directory located on the root partition. The only exception to this is chroot jails. CCE-RHEL7-CCE-TBD Add noexec Option to /dev/shm The noexec mount option can be used to prevent binaries from being executed out of /dev/shm. It can be dangerous to allow the execution of binaries from world-writable temporary storage directories such as /dev/shm. Add the noexec option to the fourth column of /etc/fstab for the line which controls mounting of /dev/shm. CM-7 MP-2 Allowing users to execute binaries from world-writable directories such as /dev/shm can expose the system to potential compromise. CCE-RHEL7-CCE-TBD Add nosuid Option to /dev/shm The nosuid mount option can be used to prevent execution of setuid programs in /dev/shm. The SUID and SGID permissions should not be required in these world-writable directories. Add the nosuid option to the fourth column of /etc/fstab for the line which controls mounting of /dev/shm. CM-7 MP-2 The presence of SUID and SGID executables should be tightly controlled. Users should not be able to execute SUID or SGID binaries from temporary storage partitions. CCE-RHEL7-CCE-TBD Bind Mount /var/tmp To /tmp The /var/tmp directory is a world-writable directory. Bind-mount it to /tmp in order to consolidate temporary storage into one location protected by the same techniques as /tmp. To do so, edit /etc/fstab and add the following line:

/tmp     /var/tmp     none     rw,nodev,noexec,nosuid,bind     0 0

See the mount(8) man page for further explanation of bind mounting. CM-7 Having multiple locations for temporary storage is not required. Unless absolutely necessary to meet requirements, the storage location /var/tmp should be bind mounted to /tmp and thus share the same protections. CCE-RHEL7-CCE-TBD Restrict Dynamic Mounting and Unmounting of Filesystems Linux includes a number of facilities for the automated addition and removal of filesystems on a running system. These facilities may be necessary in many environments, but this capability also carries some risk -- whether direct risk from allowing users to introduce arbitrary filesystems, or risk that software flaws in the automated mount facility itself could allow an attacker to compromise the system.

This command can be used to list the types of filesystems that are available to the currently executing kernel:

$ find /lib/modules/`uname -r`/kernel/fs -type f -name '*.ko'

If these filesystems are not required then they can be explicitly disabled in a configuratio file in /etc/modprobe.d. Disable Modprobe Loading of USB Storage Driver To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the usb-storage kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install usb-storage /bin/true

This will prevent the modprobe program from loading the usb-storage module, but will not prevent an administrator (or another program) from using the insmod program to load the module manually. AC-19(a) AC-19(d) AC-19(e) 1250 85 USB storage devices such as thumb drives can be used to introduce malicious software. CCE-RHEL7-CCE-TBD echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf If the system is configured to prevent the loading of the usb-storage kernel module, it will contain lines inside any file in /etc/modprobe.d or the deprecated/etc/modprobe.conf. These lines instruct the module loading system to run another program (such as /bin/true) upon a module install event. Run the following command to search for such lines in all files in /etc/modprobe.d and the deprecated /etc/modprobe.conf:

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d

Disable Kernel Support for USB via Bootloader Configuration All USB support can be disabled by adding the nousb argument to the kernel's boot loader configuration. To do so, append "nousb" to the kernel line in /etc/grub.conf as shown:

kernel /vmlinuz-VERSION ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet nousb

WARNING: Disabling all kernel support for USB will cause problems for systems with USB-based keyboards, mice, or printers. This configuration is infeasible for systems which require USB devices, which is common. AC-19(a) AC-19(d) AC-19(e) 1250 Disabling the USB subsystem within the Linux kernel at system boot will protect against potentially malicious USB devices, although it is only practical in specialized systems. CCE-RHEL7-CCE-TBD Disable Booting from USB Devices in Boot Firmware Configure the system boot firmware (historically called BIOS on PC systems) to disallow booting from USB drives. AC-19(a) AC-19(d) AC-19(e) 1250 Booting a system from a USB device would allow an attacker to circumvent any security measures provided by the operating system. Attackers could mount partitions and modify the configuration of the OS. CCE-RHEL7-CCE-TBD Assign Password to Prevent Changes to Boot Firmware Configuration Assign a password to the system boot firmware (historically called BIOS on PC systems) to require a password for any configuration changes. Assigning a password to the system boot firmware prevents anyone with physical access from configuring the system to boot from local media and circumvent the operating system's access controls. For systems in physically secure locations, such as a data center or Sensitive Compartmented Information Facility (SCIF), this risk must be weighed against the risk of administrative personnel being unable to conduct recovery operations in a timely fashion. CCE-RHEL7-CCE-TBD Disable the Automounter The autofs daemon mounts and unmounts filesystems, such as user home directories shared via NFS, on demand. In addition, autofs can be used to handle removable media, and the default configuration provides the cdrom device as /misc/cd. However, this method of providing access to removable media is not common, so autofs can almost always be disabled if NFS is not in use. Even if NFS is required, it may be possible to configure filesystem mounts statically by editing /etc/fstab rather than relying on the automounter.

The autofs service can be disabled with the following command:

$ sudo systemctl disable autofs

AC-19(a) AC-19(d) AC-19(e) 1250 85 Disabling the automounter permits the administrator to statically control filesystem mounting through /etc/fstab. CCE-RHEL7-CCE-TBD # # Disable autofs.service for all systemd targets # systemctl disable autofs.service # # Stop autofs.service if currently running # systemctl stop autofs.service To check that the autofs service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled autofs

Output should indicate the autofs service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled autofs
disabled

Run the following command to verify autofs is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active autofs

If the service is not running the command will return the following output:

inactive

Disable GNOME3 Automounting The system's default desktop environment, GNOME3, will mount devices and removable media (such as DVDs, CDs and USB flash drives) whenever they are inserted into the system. To disable automount and autorun within GNOME3, the automount, automount-open, and autorun-never settings must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory and locked in /etc/dconf/db/local.d/locks directory to prevent user modification. After the settings have been set, run dconf update. AC-19(a) AC-19(d) AC-19(e) Disabling automatic mounting in GNOME3 can prevent the introduction of malware via removable media. It will, however, also prevent desktop users from legitimate use of removable media. CCE-RHEL7-CCE-TBD These settings can be verified by running the following:

$ gsettings get org.gnome.desktop.media-handling automount
$ gsettings get org.gnome.desktop.media-handling automount-open
$ gsettings get org.gnome.desktop.media-handling autorun-never

If properly configured, the output for automount should be false. If properly configured, the output for automount-openshould be false. If properly configured, the output for autorun-never should be true. To ensure that users cannot enable automount and autorun in GNOME3, run the following:

$ grep 'automount\|autorun' /etc/dconf/db/local.d/locks/*

If properly configured, the output for automount should be /org/gnome/desktop/media-handling/automount If properly configured, the output for automount-open should be /org/gnome/desktop/media-handling/auto-open If properly configured, the output for autorun-never should be /org/gnome/desktop/media-handling/autorun-never Disable Mounting of cramfs To configure the system to prevent the cramfs kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install cramfs /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf Disable Mounting of freevxfs To configure the system to prevent the freevxfs kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install freevxfs /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf Disable Mounting of jffs2 To configure the system to prevent the jffs2 kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install jffs2 /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf Disable Mounting of hfs To configure the system to prevent the hfs kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install hfs /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf Disable Mounting of hfsplus To configure the system to prevent the hfsplus kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install hfsplus /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf Disable Mounting of squashfs To configure the system to prevent the squashfs kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install squashfs /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf Disable Mounting of udf To configure the system to prevent the udf kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install udf /bin/true

This effectively prevents usage of this uncommon filesystem. CM-7 Linux kernel modules which implement filesystems that are not needed by the local system should be disabled. CCE-RHEL7-CCE-TBD echo "install udf /bin/true" > /etc/modprobe.d/udf.conf Disable All GNOME3 Thumbnailers The system's default desktop environment, GNOME3, uses a number of different thumbnailer programs to generate thumbnails for any new or modified content in an opened folder. To disable the execution of these thumbnail applications, the disable-all setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory and locked in /etc/dconf/db/local.d/locks directory to prevent user modification. After the settings have been set, run dconf update. This effectively prevents an attacker from gaining access to a system through a flaw in GNOME3's Nautilus thumbnail creators. CM-7 An attacker with knowledge of a flaw in a GNOME3 thumbnailer application could craft a malicious file to exploit this flaw. Assuming the attacker could place the malicious file on the local filesystem (via a web upload for example) and assuming a user browses the same location using Nautilus, the malicious file would exploit the thumbnailer with the potential for malicious code execution. It is best to disable these thumbnailer applications unless they are explicitly required. CCE-RHEL7-CCE-TBD These settings can be verified by running the following:

$ gsettings get org.gnome.desktop.thumbnailers disable-all

If properly configured, the output should be true. To ensure that users cannot how long until the the screensaver locks, run the following:

$ grep disable-all /etc/dconf/db/local.d/locks/*

If properly configured, the output should be /org/gnome/desktop/thumbnailers/disable-all Verify Permissions on Important Files and Directories Permissions for many files on a system must be set restrictively to ensure sensitive information is properly protected. This section discusses important permission restrictions which can be verified to ensure that no harmful discrepancies have arisen. Verify Permissions on Files with Local Account Information and Credentials The default restrictive permissions for files which act as important security databases such as passwd, shadow, group, and gshadow files must be maintained. Many utilities need read access to the passwd file in order to function properly, but read access to the shadow file allows malicious attacks against system passwords, and should never be enabled. Verify User Who Owns shadow File To properly set the owner of /etc/shadow, run the command:

$ sudo chown root /etc/shadow

AC-6 Test attestation on 20121026 by DS The /etc/shadow file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture. CCE-26795-5 chown root /etc/shadow To check the ownership of /etc/shadow, run the command:

$ ls -lL /etc/shadow

If properly configured, the output should indicate the following owner: root Verify Group Who Owns shadow File To properly set the group owner of /etc/shadow, run the command:

$ sudo chgrp root xsl:value-of select="@file"/> 

AC-6 Test attestation on 20121026 by DS The /etc/shadow file stores password hashes. Protection of this file is critical for system security. CCE-27125-4 chgrp root /etc/shadow To check the group ownership of /etc/shadow, run the command:

$ ls -lL /etc/shadow

If properly configured, the output should indicate the following group-owner. root Verify Permissions on shadow File To properly set the permissions of /etc/shadow, run the command:

$ sudo chmod 0000 /etc/shadow

AC-6 Test attestation on 20121026 by DS The /etc/shadow file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture. CCE-27100-7 chmod 0000 /etc/shadow To check the permissions of /etc/shadow, run the command:

$ ls -l /etc/shadow

If properly configured, the output should indicate the following permissions: ---------- Verify User Who Owns group File To properly set the owner of /etc/group, run the command:

$ sudo chown root /etc/group

AC-6 Test attestation on 20121026 by DS The /etc/group file contains information regarding groups that are configured on the system. Protection of this file is important for system security. CCE-26933-2 chown root /etc/group To check the ownership of /etc/group, run the command:

$ ls -lL /etc/group

If properly configured, the output should indicate the following owner: root Verify Group Who Owns group File To properly set the group owner of /etc/group, run the command:

$ sudo chgrp root xsl:value-of select="@file"/> 

AC-6 Test attestation on 20121026 by DS The /etc/group file contains information regarding groups that are configured on the system. Protection of this file is important for system security. CCE-27037-1 chgrp root /etc/group To check the group ownership of /etc/group, run the command:

$ ls -lL /etc/group

If properly configured, the output should indicate the following group-owner. root Verify Permissions on group File To properly set the permissions of /etc/group, run the command:

$ sudo chmod 644 /etc/group

AC-6 Test attestation on 20121026 by DS The /etc/group file contains information regarding groups that are configured on the system. Protection of this file is important for system security. CCE-26949-8 chmod 644 /etc/group To check the permissions of /etc/group, run the command:

$ ls -l /etc/group

If properly configured, the output should indicate the following permissions: -rw-r--r-- Verify User Who Owns gshadow File To properly set the owner of /etc/gshadow, run the command:

$ sudo chown root /etc/gshadow

AC-6 Test attestation on 20121026 by DS The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security. CCE-27161-9 chown root /etc/gshadow To check the ownership of /etc/gshadow, run the command:

$ ls -lL /etc/gshadow

If properly configured, the output should indicate the following owner: root Verify Group Who Owns gshadow File To properly set the group owner of /etc/gshadow, run the command:

$ sudo chgrp root xsl:value-of select="@file"/> 

AC-6 Test attestation on 20121026 by DS The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security. CCE-26840-9 chgrp root /etc/gshadow To check the group ownership of /etc/gshadow, run the command:

$ ls -lL /etc/gshadow

If properly configured, the output should indicate the following group-owner. root Verify Permissions on gshadow File To properly set the permissions of /etc/gshadow, run the command:

$ sudo chmod 0000 /etc/gshadow

AC-6 Test attestation on 20121026 by DS The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security. CCE-27162-7 chmod 0000 /etc/gshadow To check the permissions of /etc/gshadow, run the command:

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions: ---------- Verify User Who Owns passwd File To properly set the owner of /etc/passwd, run the command:

$ sudo chown root /etc/passwd

AC-6 Test attestation on 20121026 by DS The /etc/passwd file contains information about the users that are configured on the system. Protection of this file is critical for system security. CCE-27138-7 chown root /etc/passwd To check the ownership of /etc/passwd, run the command:

$ ls -lL /etc/passwd

If properly configured, the output should indicate the following owner: root Verify Group Who Owns passwd File To properly set the group owner of /etc/passwd, run the command:

$ sudo chgrp root xsl:value-of select="@file"/> 

AC-6 Test attestation on 20121026 by DS The /etc/passwd file contains information about the users that are configured on the system. Protection of this file is critical for system security. CCE-26639-5 chgrp root /etc/passwd To check the group ownership of /etc/passwd, run the command:

$ ls -lL /etc/passwd

If properly configured, the output should indicate the following group-owner. root Verify Permissions on passwd File To properly set the permissions of /etc/passwd, run the command:

$ sudo chmod 0644 /etc/passwd

AC-6 Test attestation on 20121026 by DS If the /etc/passwd file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security. CCE-26887-0 chmod 0644 /etc/passwd To check the permissions of /etc/passwd, run the command:

$ ls -l /etc/passwd

If properly configured, the output should indicate the following permissions: -rw-r--r-- Verify File Permissions Within Some Important Directories Some directories contain files whose confidentiality or integrity is notably important and may also be susceptible to misconfiguration over time, particularly if unpackaged software is installed. As such, an argument exists to verify that files' permissions within these directories remain configured correctly and restrictively. Verify that Shared Library Files Have Restrictive Permissions System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:

/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are stored in /lib/modules. All files in these directories should not be group-writable or world-writable. If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:

$ sudo chmod go-w FILE

AC-6 Test attestation on 20121026 by DS Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system. CCE-26966-2 DIRS="/lib /lib64 /usr/lib /usr/lib64" for dirPath in $DIRS; do find "$dirPath" -perm /022 -type f -exec chmod go-w '{}' \; done Shared libraries are stored in the following directories:

/lib
/lib64
/usr/lib
/usr/lib64

To find shared libraries that are group-writable or world-writable, run the following command for each directory DIR which contains shared libraries:

$ sudo find -L DIR -perm /022 -type f

Verify that Shared Library Files Have Root Ownership System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:

/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are also stored in /lib/modules. All files in these directories should be owned by the root user. If the directory, or any file in these directories, is found to be owned by a user other than root correct its ownership with the following command:

$ sudo chown root FILE

AC-6 Test attestation on 20130914 by swells Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system. CCE-26648-6 for LIBDIR in /usr/lib /usr/lib64 /lib /lib64 do if [ -d $LIBDIR ] then find -L $LIBDIR \! -user root -exec chown root {} \; fi done Shared libraries are stored in the following directories:

/lib
/lib64
/usr/lib
/usr/lib64

For each of these directories, run the following command to find files not owned by root:

$ sudo find -L $DIR \! -user root -exec chown root {} \;

Verify that System Executables Have Restrictive Permissions System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. If any file FILE in these directories is found to be group-writable or world-writable, correct its permission with the following command:

$ sudo chmod go-w FILE

AC-6 System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted. CCE-27075-1 DIRS="/bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin" for dirPath in $DIRS; do find "$dirPath" -perm /022 -exec chmod go-w '{}' \; done System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

To find system executables that are group-writable or world-writable, run the following command for each directory DIR which contains system executables:

$ sudo find -L DIR -perm /022 -type f

Verify that System Executables Have Root Ownership System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should be owned by the root user. If any file FILE in these directories is found to be owned by a user other than root, correct its ownership with the following command:

$ sudo chown root FILE

AC-6 System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted. CCE-27119-7 find /bin/ \ /usr/bin/ \ /usr/local/bin/ \ /sbin/ \ /usr/sbin/ \ /usr/local/sbin/ \ \! -user root -execdir chown root {} \; System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

To find system executables that are not owned by root, run the following command for each directory DIR which contains system executables:

$ sudo find DIR/ \! -user root

Verify that All World-Writable Directories Have Sticky Bits Set When the so-called 'sticky bit' is set on a directory, only the owner of a given file may remove that file from the directory. Without the sticky bit, any user with write access to a directory may remove any file in the directory. Setting the sticky bit prevents users from removing each other's files. In cases where there is no reason for a directory to be world-writable, a better solution is to remove that permission rather than to set the sticky bit. However, if a directory is used by a particular application, consult that application's documentation instead of blindly changing modes.
To set the sticky bit on a world-writable directory DIR, run the following command:

$ sudo chmod +t DIR

AC-6 Test attestation on 20120929 by swells Failing to set the sticky bit on public directories allows unauthorized users to delete files in the directory structure.

The only authorized public directories are those temporary directories supplied with the system, or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system, by users for temporary file storage (such as /tmp), and for directories requiring global read/write access. CCE-RHEL7-CCE-TBD To find world-writable directories that lack the sticky bit, run the following command:

$ sudo find / -xdev -type d -perm 002 ! -perm 1000

Ensure No World-Writable Files Exist It is generally a good idea to remove global (other) write access to a file when it is discovered. However, check with documentation for specific applications before making changes. Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured application or user account. AC-6 Data in world-writable files can be modified by any user on the system. In almost all circumstances, files can be configured using a combination of user and group permissions to support whatever legitimate access is needed without the risk caused by world-writable files. CCE-RHEL7-CCE-TBD To find world-writable files, run the following command:

$ sudo find / -xdev -type f -perm -002

Ensure All SGID Executables Are Authorized The SGID (set group id) bit should be set only on files that were installed via authorized means. A straightforward means of identifying unauthorized SGID files is determine if any were not installed as part of an RPM package, which is cryptographically verified. Investigate the origin of any unpackaged SGID files. Executable files with the SGID permission run with the privileges of the owner of the file. SGID files of uncertain provenance could allow for unprivileged users to elevate privileges. The presence of these files should be strictly controlled on the system. CCE-RHEL7-CCE-TBD To find world-writable files, run the following command:

$ sudo find / -xdev -type f -perm -002

Ensure All SUID Executables Are Authorized The SUID (set user id) bit should be set only on files that were installed via authorized means. A straightforward means of identifying unauthorized SGID files is determine if any were not installed as part of an RPM package, which is cryptographically verified. Investigate the origin of any unpackaged SUID files. AC-6(1) Executable files with the SUID permission run with the privileges of the owner of the file. SUID files of uncertain provenance could allow for unprivileged users to elevate privileges. The presence of these files should be strictly controlled on the system. CCE-RHEL7-CCE-TBD To find world-writable files, run the following command:

$ sudo find / -xdev -type f -perm -002

Ensure All Files Are Owned by a User If any files are not owned by a user, then the cause of their lack of ownership should be investigated. Following this, the files should be deleted or assigned to an appropriate user. AC-6 224 Unowned files do not directly imply a security problem, but they are generally a sign that something is amiss. They may be caused by an intruder, by incorrect software installation or draft software removal, or by failure to remove all files belonging to a deleted account. The files should be repaired so they will not cause problems when accounts are created in the future, and the cause should be discovered and addressed. CCE-RHEL7-CCE-TBD The following command will discover and print any files on local partitions which do not belong to a valid user. Run it once for each local partition PART:

$ sudo find PART -xdev -nouser -print

Ensure All Files Are Owned by a Group If any files are not owned by a group, then the cause of their lack of group-ownership should be investigated. Following this, the files should be deleted or assigned to an appropriate group. AC-6 224 Unowned files do not directly imply a security problem, but they are generally a sign that something is amiss. They may be caused by an intruder, by incorrect software installation or draft software removal, or by failure to remove all files belonging to a deleted account. The files should be repaired so they will not cause problems when accounts are created in the future, and the cause should be discovered and addressed. CCE-RHEL7-CCE-TBD The following command will discover and print any files on local partitions which do not belong to a valid group. Run it once for each local partition PART:

$ sudo find PART -xdev -nogroup -print

Ensure All World-Writable Directories Are Owned by a System Account All directories in local partitions which are world-writable should be owned by root or another system account. If any world-writable directories are not owned by a system account, this should be investigated. Following this, the files should be deleted or assigned to an appropriate group. AC-6 Test attestation on 20120929 by swells Allowing a user account to own a world-writable directory is undesirable because it allows the owner of that directory to remove or replace any files that may be placed in the directory by other users. CCE-RHEL7-CCE-TBD The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a uid lower than 500. Run it once for each local partition PART:

$ sudo find PART -xdev -type d -perm -0002 -uid +499 -print

Restrict Programs from Dangerous Execution Patterns The recommendations in this section are designed to ensure that the system's features to protect against potentially dangerous program execution are activated. These protections are applied at the system initialization or kernel level, and defend against certain types of badly-configured or compromised programs. Daemon Umask The umask is a per-process setting which limits the default permissions for creation of new files and directories. The system includes initialization scripts which set the default umask for system daemons. daemon umask Enter umask for daemons 022 022 027 Set Daemon Umask The file /etc/init.d/functions includes initialization parameters for most or all daemons started at boot time. The default umask of 022 prevents creation of group- or world-writable files. To set the default umask for daemons, edit the following line, inserting 022 or 027 for UMASK appropriately:

umask UMASK

Setting the umask to too restrictive a setting can cause serious errors at runtime. Many daemons on the system already individually restrict themselves to a umask of 077 in their own init scripts. AC-6 Test attestation on 20140912 by JL The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions. CCE-RHEL7-CCE-TBD var_umask_for_daemons="" grep -q ^umask /etc/init.d/functions && \ sed -i "s/umask.*/umask $var_umask_for_daemons/g" /etc/init.d/functions if ! [ $? -eq 0 ]; then echo "umask $var_umask_for_daemons" >> /etc/init.d/functions fi To check the value of the umask, run the following command:

$ grep umask /etc/init.d/functions

The output should show either 022 or 027. Disable Core Dumps A core dump file is the memory image of an executable program when it was terminated by the operating system due to errant behavior. In most cases, only software developers legitimately need to access these files. The core dump files may also contain sensitive information, or unnecessarily occupy large amounts of disk space.

Once a hard limit is set in /etc/security/limits.conf, a user cannot increase that limit within his or her own session. If access to core dumps is required, consider restricting them to only certain users or groups. See the limits.conf man page for more information.

The core dumps of setuid programs are further protected. The sysctl variable fs.suid_dumpable controls whether the kernel allows core dumps from these programs at all. The default value of 0 is recommended. Disable Core Dumps for All Users To disable core dumps for all users, add the following line to /etc/security/limits.conf:

*     hard   core    0

SC-5 A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems. CCE-RHEL7-CCE-TBD echo "* hard core 0" >> /etc/security/limits.conf To verify that core dumps are disabled for all users, run the following command:

$ grep core /etc/security/limits.conf

The output should be:

*     hard   core    0

Disable Core Dumps for SUID programs To set the runtime status of the fs.suid_dumpable kernel parameter, run the following command:

$ sudo sysctl -w fs.suid_dumpable=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

fs.suid_dumpable = 0

SI-11 The core dump of a setuid program is more likely to contain sensitive data, as the program itself runs with greater privileges than the user who initiated execution of the program. Disabling the ability for any setuid program to write a core file decreases the risk of unauthorized access of such data. CCE-RHEL7-CCE-TBD # # Set runtime for fs.suid_dumpable # sysctl -q -n -w fs.suid_dumpable=0 # # If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0" # else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf # if grep --silent ^fs.suid_dumpable /etc/sysctl.conf ; then sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/g' /etc/sysctl.conf else echo -e "\n# Set fs.suid_dumpable to 0 per security requirements" >> /etc/sysctl.conf echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf fi The status of the fs.suid_dumpable kernel parameter can be queried by running the following command:

$ sysctl fs.suid_dumpable

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable ExecShield ExecShield describes kernel features that provide protection against exploitation of memory corruption errors such as buffer overflows. These features include random placement of the stack and other memory regions, prevention of execution in memory that should only hold data, and special handling of text buffers. These protections are enabled by default on 32-bit systems and controlled through sysctl variables kernel.exec-shield and kernel.randomize_va_space. On the latest 64-bit systems, kernel.exec-shield cannot be enabled or disabled with sysctl. Enable ExecShield By default on Red Hat Enterprise Linux 7 64-bit systems, ExecShield is enabled and can only be disabled if the hardware does not support ExecShield or is disabled in /etc/default/grub. For Red Hat Enterprise Linux 7 32-bit systems, sysctl can be used to enable ExecShield. Test attestation on 20121024 by DS ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range. This is enabled by default on the latest Red Hat and Fedora systems if supported by the hardware. CCE-RHEL7-CCE-TBD # # Set runtime for kernel.exec-shield # sysctl -q -n -w kernel.exec-shield=1 # # If kernel.exec-shield present in /etc/sysctl.conf, change value to "1" # else, add "kernel.exec-shield = 1" to /etc/sysctl.conf # if grep --silent ^kernel.exec-shield /etc/sysctl.conf ; then sed -i 's/^kernel.exec-shield.*/kernel.exec-shield = 1/g' /etc/sysctl.conf else echo -e "\n# Set kernel.exec-shield to 1 per security requirements" >> /etc/sysctl.conf echo "kernel.exec-shield = 1" >> /etc/sysctl.conf fi To verify ExecShield is enabled on 64-bit Red Hat Enterprise Linux 7 systems, run the following command:

$ dmesg | grep '[NX|DX]*protection'

The output should not contain 'disabled by kernel command line option'. To verify that ExecShield has not been disabled in the kernel configuration, run the following command:

$ sudo grep noexec /boot/grub2/grub.cfg

The output should not return noexec=off. For 32-bit Red Hat Enterprise Linux 7 systems, run the following command:

$ sysctl kernel.exec-shield

The output should be:


    To set the runtime status of the kernel.exec-shield kernel parameter,
    run the following command:
    

$ sudo sysctl -w kernel.exec-shield=1


    If this is not the system's default value, add the following line to /etc/sysctl.conf:
    

kernel.exec-shield = 1

Enable Randomized Layout of Virtual Address Space To set the runtime status of the kernel.randomize_va_space kernel parameter, run the following command:

$ sudo sysctl -w kernel.randomize_va_space=2

If this is not the system's default value, add the following line to /etc/sysctl.conf:

kernel.randomize_va_space = 2

Test attestation on 20121024 by DS Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code they have introduced into a process's address space during an attempt at exploitation. Additionally, ASLR makes it more difficult for an attacker to know the location of existing code in order to re-purpose it using return oriented programming (ROP) techniques. CCE-RHEL7-CCE-TBD # # Set runtime for kernel.randomize_va_space # sysctl -q -n -w kernel.randomize_va_space=2 # # If kernel.randomize_va_space present in /etc/sysctl.conf, change value to "2" # else, add "kernel.randomize_va_space = 2" to /etc/sysctl.conf # if grep --silent ^kernel.randomize_va_space /etc/sysctl.conf ; then sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/g' /etc/sysctl.conf else echo -e "\n# Set kernel.randomize_va_space to 2 per security requirements" >> /etc/sysctl.conf echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf fi The status of the kernel.randomize_va_space kernel parameter can be queried by running the following command:

$ sysctl kernel.randomize_va_space

The output of the command should indicate a value of 2. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Execute Disable (XD) or No Execute (NX) Support on x86 Systems Recent processors in the x86 family support the ability to prevent code execution on a per memory page basis. Generically and on AMD processors, this ability is called No Execute (NX), while on Intel processors it is called Execute Disable (XD). This ability can help prevent exploitation of buffer overflow vulnerabilities and should be activated whenever possible. Extra steps must be taken to ensure that this protection is enabled, particularly on 32-bit x86 systems. Other processors, such as Itanium and POWER, have included such support since inception and the standard kernel for those platforms supports the feature. This is enabled by default on the latest Red Hat and Fedora systems if supported by the hardware. Install PAE Kernel on Supported 32-bit x86 Systems Systems that are using the 64-bit x86 kernel package do not need to install the kernel-PAE package because the 64-bit x86 kernel already includes this support. However, if the system is 32-bit and also supports the PAE and NX features as determined in the previous section, the kernel-PAE package should be installed to enable XD or NX support:

$ sudo yum install kernel-PAE

The installation process should also have configured the bootloader to load the new kernel at boot. Verify this at reboot and modify /etc/default/grub if necessary. The kernel-PAE package should not be installed on older systems that do not support the XD or NX bit, as this may prevent them from booting. On 32-bit systems that support the XD or NX bit, the vendor-supplied PAE kernel is required to enable either Execute Disable (XD) or No Execute (NX) support. CCE-RHEL7-CCE-TBD Enable NX or XD Support in the BIOS Reboot the system and enter the BIOS or Setup configuration menu. Navigate the BIOS configuration menu and make sure that the option is enabled. The setting may be located under a Security section. Look for Execute Disable (XD) on Intel-based systems and No Execute (NX) on AMD-based systems. Computers with the ability to prevent this type of code execution frequently put an option in the BIOS that will allow users to turn the feature on or off at will. CCE-RHEL7-CCE-TBD Restrict Access to Kernel Message Buffer To set the runtime status of the kernel.dmesg_restrict kernel parameter, run the following command:

$ sudo sysctl -w kernel.dmesg_restrict=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

kernel.dmesg_restrict = 1

Unprivileged access to the kernel syslog can expose sensitive kernel address information. CCE-RHEL7-CCE-TBD The status of the kernel.dmesg_restrict kernel parameter can be queried by running the following command:

$ sysctl kernel.dmesg_restrict

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. SELinux SELinux is a feature of the Linux kernel which can be used to guard against misconfigured or compromised programs. SELinux enforces the idea that programs should be limited in what files they can access and what actions they can take.

The default SELinux policy, as configured on RHEL 7, has been sufficiently developed and debugged that it should be usable on almost any Red Hat machine with minimal configuration and a small amount of system administrator training. This policy prevents system services - including most of the common network-visible services such as mail servers, FTP servers, and DNS servers - from accessing files which those services have no valid reason to access. This action alone prevents a huge amount of possible damage from network attacks against services, from trojaned software, and so forth.

This guide recommends that SELinux be enabled using the default (targeted) policy on every Red Hat system, unless that system has unusual requirements which make a stronger policy appropriate. SELinux state enforcing - SELinux security policy is enforced.
permissive - SELinux prints warnings instead of enforcing.
disabled - SELinux is fully disabled. enforcing enforcing permissive disabled SELinux policy Type of policy in use. Possible values are:
targeted - Only targeted network daemons are protected.
strict - Full SELinux protection.
mls - Multiple levels of security targeted targeted mls Ensure SELinux Not Disabled in /etc/grub.conf SELinux can be disabled at boot time by an argument in /etc/grub.conf. Remove any instances of selinux=0 from the kernel arguments in that file to prevent SELinux from being disabled at boot. AC-3 AC-3(3) AC-6 AU-9 22 32 Test attestation on 20121024 by DS Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation. CCE-RHEL7-CCE-TBD Inspect /etc/grub.conf for any instances of selinux=0 in the kernel boot arguments. Presence of selinux=0 indicates that SELinux is disabled at boot time. Ensure SELinux State is Enforcing The SELinux state should be set to enforcing at system boot time. In the file /etc/selinux/config, add or correct the following line to configure the system to boot into enforcing mode:

SELINUX=enforcing

AC-3 AC-3(3) AC-4 AC-6 AU-9 Test attestation on 20121024 by DS Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges. CCE-26800-3 var_selinux_state="" grep -q ^SELINUX= /etc/selinux/config && \ sed -i "s/SELINUX=.*/SELINUX=$var_selinux_state/g" /etc/selinux/config if ! [ $? -eq 0 ]; then echo "SELINUX=$var_selinux_state" >> /etc/selinux/config fi Check the file /etc/selinux/config and ensure the following line appears:

SELINUX=enforcing

Configure SELinux Policy The SELinux targeted policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in /etc/selinux/config:

SELINUXTYPE=targeted

Other policies, such as mls, provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases. AC-3 AC-3(3) AC-4 AC-6 AU-9 Test attestation on 20121024 by DS Setting the SELinux policy to targeted or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services. Note: During the development or debugging of SELinux modules, it is common to temporarily place non-production systems in permissive mode. In such temporary cases, SELinux policies should be developed, and once work is completed, the system should be reconfigured to . CCE-27135-3 var_selinux_policy_name="" grep -q ^SELINUXTYPE /etc/selinux/config && \ sed -i "s/SELINUXTYPE=.*/SELINUXTYPE=$var_selinux_policy_name/g" /etc/selinux/config if ! [ $? -eq 0 ]; then echo "SELINUXTYPE=$var_selinux_policy_name" >> /etc/selinux/config fi Check the file /etc/selinux/config and ensure the following line appears:

SELINUXTYPE=targeted

Uninstall setroubleshoot Package The SETroubleshoot service notifies desktop users of SELinux denials. The service provides information around configuration errors, unauthorized intrusions, and other potential errors. The setroubleshoot package can be removed with the following command:

$ sudo yum erase setroubleshoot

The SETroubleshoot service is an unnecessary daemon to have running on a server CCE- Uninstall mcstrans Package The mcstransd daemon provides category label information to client processes requesting information. The label translations are defined in /etc/selinux/targeted/setrans.conf. The mcstrans package can be removed with the following command:

$ sudo yum erase mcstrans

Since this service is not used very often, disable it to reduce the amount of potentially vulnerable code running on the system. NOTE: This rule was added in support of the CIS RHEL6 v1.2.0 benchmark. Please note that Red Hat does not feel this rule is security relevant. CCE- Ensure No Daemons are Unconfined by SELinux Daemons for which the SELinux policy does not contain rules will inherit the context of the parent process. Because daemons are launched during startup and descend from the init process, they inherit the initrc_t context.

To check for unconfined daemons, run the following command:

$ sudo ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'

It should produce no output in a well-configured system. AC-6 AU-9 CM-7 Daemons which run with the initrc_t context may cause AVC denials, or allow privileges that the daemon does not require. CCE-RHEL7-CCE-TBD Ensure No Device Files are Unlabeled by SELinux Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type unlabeled_t, investigate the cause and correct the file's context. AC-6 AU-9 CM-7 22 32 Test attestation on 20121024 by DS If a device file carries the SELinux type unlabeled_t, then SELinux cannot properly restrict access to the device file. CCE-RHEL7-CCE-TBD To check for unlabeled device files, run the following command:

$sudo find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"

It should produce no output in a well-configured system. Account and Access Control In traditional Unix security, if an attacker gains shell access to a certain login account, they can perform any action or access any file to which that account has access. Therefore, making it more difficult for unauthorized people to gain shell access to accounts, particularly to privileged accounts, is a necessary part of securing a system. This section introduces mechanisms for restricting access to accounts under RHEL 7. Protect Accounts by Restricting Password-Based Login Conventionally, Unix shell accounts are accessed by providing a username and password to a login program, which tests these values for correctness using the /etc/passwd and /etc/shadow files. Password-based login is vulnerable to guessing of weak passwords, and to sniffing and man-in-the-middle attacks against passwords entered over a network or at an insecure console. Therefore, mechanisms for accessing accounts by entering usernames and passwords should be restricted to those which are operationally necessary. Restrict Root Logins Direct root logins should be allowed only for emergency use. In normal situations, the administrator should access the system via a unique unprivileged account, and then use su or sudo to execute privileged commands. Discouraging administrators from accessing the root account directly ensures an audit trail in organizations with multiple administrators. Locking down the channels through which root can connect directly also reduces opportunities for password-guessing against the root account. The login program uses the file /etc/securetty to determine which interfaces should allow root logins. The virtual devices /dev/console and /dev/tty* represent the system consoles (accessible via the Ctrl-Alt-F1 through Ctrl-Alt-F6 keyboard sequences on a default installation). The default securetty file also contains /dev/vc/*. These are likely to be deprecated in most environments, but may be retained for compatibility. Root should also be prohibited from connecting via network protocols. Other sections of this document include guidance describing how to prevent root from logging in via SSH. Direct root Logins Not Allowed To further limit access to the root account, administrators can disable root logins at the console by editing the /etc/securetty file. This file lists all devices the root user is allowed to login to. If the file does not exist at all, the root user can login through any communication device on the system, whether via the console or via a raw network interface. This is dangerous as user can login to his machine as root via Telnet, which sends the password in plain text over the network. By default, Red Hat Enteprise Linux's /etc/securetty file only allows the root user to login at the console physically attached to the machine. To prevent root from logging in, remove the contents of this file. To prevent direct root logins, remove the contents of this file by typing the following command:


$ sudo echo > /etc/securetty

IA-2(1) Test attestation on 20121024 by DS Disabling direct root logins ensures proper accountability and multifactor authentication to privileged accounts. Users will first login, then escalate to privileged (root) access via su / sudo. This is required for FISMA Low and FISMA Moderate systems. CCE-RHEL7-CCE-TBD To ensure root may not directly login to the system over physical consoles, run the following command:

cat /etc/securetty

If any output is returned, this is a finding. Restrict Virtual Console Root Logins To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in /etc/securetty:

vc/1
vc/2
vc/3
vc/4

AC-6(2) 770 Test attestation on 20121024 by DS Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account. CCE-RHEL7-CCE-TBD sed -i '/^vc\//d' /etc/securetty To check for virtual console entries which permit root login, run the following command:

$ sudo grep ^vc/[0-9] /etc/securetty

If any output is returned, then root logins over virtual console devices is permitted. Restrict Serial Port Root Logins To restrict root logins on serial ports, ensure lines of this form do not appear in /etc/securetty:

ttyS0
ttyS1

AC-6(2) 770 Test attestation on 20121024 by DS Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account. CCE-RHEL7-CCE-TBD To check for serial port entries which permit root login, run the following command:

$ sudo grep ^ttyS/[0-9] /etc/securetty

If any output is returned, then root login over serial ports is permitted. Restrict Web Browser Use for Administrative Accounts Enforce policy requiring administrative accounts use web browsers only for local service administration. If a browser vulnerability is exploited while running with administrative privileges, the entire system could be compromised. Specific exceptions for local service administration should be documented in site-defined policy. CCE-RHEL7-CCE-TBD Check the root home directory for a .mozilla directory. If one exists, ensure browsing is limited to local service administration. Ensure that System Accounts Do Not Run a Shell Upon Login Some accounts are not associated with a human user of the system, and exist to perform some administrative function. Should an attacker be able to log into these accounts, they should not be granted access to a shell.

The login shell for each local account is stored in the last field of each line in /etc/passwd. System accounts are those user accounts with a user ID less than 1000. The user ID is stored in the third field. If any system account SYSACCT (other than root) has a login shell, disable it with the command:

$ sudo usermod -s /sbin/nologin SYSACCT

Do not perform the steps in this section on the root account. Doing so might cause the system to become inaccessible. AC-2 Test attestation on 20121024 by DS Ensuring shells are not given to system accounts upon login makes it more difficult for attackers to make use of system accounts. CCE-26448-1 To obtain a listing of all users, their UIDs, and their shells, run the command:

$ awk -F: '{print $1 ":" $3 ":" $7}' /etc/passwd

Identify the system accounts from this listing. These will primarily be the accounts with UID numbers less than 1000, other than root. Verify Only Root Has UID 0 If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed. AC-6 IA-2(1) Test attestation on 20121024 by DS An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner. CCE-27175-9 awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | xargs passwd -l To list all password file entries for accounts with UID 0, run the following command:

$ awk -F: '($3 == "0") {print}' /etc/passwd

This should print only one line, for the user root. Root Path Must Be Vendor Default Assuming root shell is bash, edit the following files:

~/.profile

~/.bashrc

Change any PATH variables to the vendor default for root and remove any empty PATH entries or references to relative paths. SA-8 Test attestation on 20121024 by DS The root account's executable search path must be the vendor default, and must contain only absolute paths. CCE-RHEL7-CCE-TBD To view the root user's PATH, run the following command:

$ sudo env | grep PATH

If correctly configured, the PATH must: use vendor default settings, have no empty entries, and have no entries beginning with a character other than a slash (/). Verify Proper Storage and Existence of Password Hashes By default, password hashes for local accounts are stored in the second field (colon-separated) in /etc/shadow. This file should be readable only by processes running with root credentials, preventing users from casually accessing others' password hashes and attempting to crack them. However, it remains possible to misconfigure the system and store password hashes in world-readable files such as /etc/passwd, or to even store passwords themselves in plaintext on the system. Using system-provided tools for password change/creation should allow administrators to avoid such misconfiguration. Prevent Log In to Accounts With Empty Password If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication. Remove any instances of the nullok option in /etc/pam.d/system-auth to prevent logins with empty passwords. IA-5(b) IA-5(c) IA-5(1)(a) Test attestation on 20121024 by DS If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments. CCE-27010-8 sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth To verify that null passwords cannot be used, run the following command:

$ grep nullok /etc/pam.d/system-auth

If this produces any output, it may be possible to log into accounts with empty passwords. Verify All Account Password Hashes are Shadowed If any password hashes are stored in /etc/passwd (in the second field, instead of an x), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely. IA-5(h) Test attestation on 20121024 by DS The hashes for all user account passwords should be stored in the file /etc/shadow and never in /etc/passwd, which is readable by all users. CCE-27144-5 To check that no password hashes are stored in /etc/passwd, run the following command:

$ awk -F: '($2 != "x") {print}' /etc/passwd

If it produces any output, then a password hash is stored in /etc/passwd. All GIDs referenced in /etc/passwd must be defined in /etc/group Add a group to the system for each GID referenced without a corresponding group. 366 Test attestation on 20121024 by DS Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights. CCE-RHEL7-CCE-TBD To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command:

$ sudo pwck -qr

There should be no output. Verify No netrc Files Exist The .netrc files contain login information used to auto-login into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any .netrc files should be removed. IA-5(h) AC-3 196 Unencrypted passwords for remote FTP servers may be stored in .netrc files. DoD policy requires passwords be encrypted in storage and not used in access scripts. CCE-RHEL7-CCE-TBD To check the system for the existence of any .netrc files, run the following command:

$ sudo find /home -xdev -name .netrc

Set Password Expiration Parameters The file /etc/login.defs controls several password-related settings. Programs such as passwd, su, and login consult /etc/login.defs to determine behavior with regard to password aging, expiration warnings, and length. See the man page login.defs(5) for more information.

Users should be forced to change their passwords, in order to decrease the utility of compromised passwords. However, the need to change passwords often should be balanced against the risk that users will reuse or write down passwords if forced to change them too often. Forcing password changes every 90-360 days, depending on the environment, is recommended. Set the appropriate value as PASS_MAX_DAYS and apply it to existing accounts with the -M flag.

The PASS_MIN_DAYS (-m) setting prevents password changes for 7 days after the first change, to discourage password cycling. If you use this setting, train users to contact an administrator for an emergency password change in case a new password becomes compromised. The PASS_WARN_AGE (-W) setting gives users 7 days of warnings at login time that their passwords are about to expire.

For example, for each existing human user USER, expiration parameters could be adjusted to a 180 day maximum password age, 7 day minimum password age, and 7 day warning period with the following command:

$ sudo chage -M 180 -m 7 -W 7 USER

minimum password length Minimum number of characters in password This will only check new passwords 14 6 8 10 12 14 maximum password age Maximum age of password in days This will only apply to newly created accounts 60 60 90 120 180 minimum password age Minimum age of password in days This will only apply to newly created accounts 7 7 5 2 1 0 warning days before password expires The number of days' warning given before a password expires. This will only apply to newly created accounts 7 0 7 14 Set Password Minimum Length in login.defs To specify password length requirements for new accounts, edit the file /etc/login.defs and add or correct the following lines:

PASS_MIN_LEN 14



The DoD requirement is 14. The FISMA requirement is 12. If a program consults /etc/login.defs and also another PAM module (such as pam_pwquality) during a password change operation, then the most restrictive must be satisfied. See PAM section for more information about enforcing password quality requirements. IA-5(f) IA-5(1)(a) Test attestation on 20121026 by DS Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result. CCE-27123-9 var_accounts_password_minlen_login_defs="" grep -q ^PASS_MIN_LEN /etc/login.defs && \ sed -i "s/PASS_MIN_LEN.*/PASS_MIN_LEN $var_accounts_password_minlen_login_defs/g" /etc/login.defs if ! [ $? -eq 0 ]; then echo "PASS_MIN_LEN $var_accounts_password_minlen_login_defs" >> /etc/login.defs fi To check the minimum password length, run the command:

$ grep PASS_MIN_LEN /etc/login.defs

The DoD requirement is 14. Set Password Minimum Age To specify password minimum age for new accounts, edit the file /etc/login.defs and add or correct the following line, replacing DAYS appropriately:

PASS_MIN_DAYS DAYS

A value of 1 day is considered for sufficient for many environments. The DoD requirement is 1. IA-5(f) IA-5(1)(d) 198 75 Test attestation on 20121026 by DS Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement. CCE-27002-5 var_accounts_minimum_age_login_defs="" grep -q ^PASS_MIN_DAYS /etc/login.defs && \ sed -i "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS $var_accounts_minimum_age_login_defs/g" /etc/login.defs if ! [ $? -eq 0 ]; then echo "PASS_MIN_DAYS $var_accounts_minimum_age_login_defs" >> /etc/login.defs fi To check the minimum password age, run the command:

$ grep PASS_MIN_DAYS /etc/login.defs

The DoD and FISMA requirement is 1. Set Password Maximum Age To specify password maximum age for new accounts, edit the file /etc/login.defs and add or correct the following line, replacing DAYS appropriately:

PASS_MAX_DAYS DAYS

A value of 180 days is sufficient for many environments. The DoD requirement is 60. IA-5(f) IA-5(g) IA-5(1)(d) 180 199 76 Test attestation on 20121026 by DS Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise. CCE-27051-2 var_accounts_maximum_age_login_defs="" grep -q ^PASS_MAX_DAYS /etc/login.defs && \ sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS $var_accounts_maximum_age_login_defs/g" /etc/login.defs if ! [ $? -eq 0 ]; then echo "PASS_MAX_DAYS $var_accounts_maximum_age_login_defs" >> /etc/login.defs fi To check the maximum password age, run the command:

$ grep PASS_MAX_DAYS /etc/login.defs

The DoD and FISMA requirement is 60. A value of 180 days is sufficient for many environments. Set Password Warning Age To specify how many days prior to password expiration that a warning will be issued to users, edit the file /etc/login.defs and add or correct the following line, replacing DAYS appropriately:

PASS_WARN_AGE DAYS

The DoD requirement is 7. AC-2(2) IA-5(f) Test attestation on 20121026 by DS Setting the password warning age enables users to make the change at a practical time. CCE-26486-1 var_accounts_password_warn_age_login_defs="" grep -q ^PASS_WARN_AGE /etc/login.defs && \ sed -i "s/PASS_WARN_AGE.*/PASS_WARN_AGE $var_accounts_password_warn_age_login_defs/g" /etc/login.defs if ! [ $? -eq 0 ]; then echo "PASS_WARN_AGE $var_accounts_password_warn_age_login_defs" >> /etc/login.defs fi To check the password warning age, run the command:

$ grep PASS_WARN_AGE /etc/login.defs

The DoD requirement is 7. Set Account Expiration Parameters Accounts can be configured to be automatically disabled after a certain time period, meaning that they will require administrator interaction to become usable again. Expiration of accounts after inactivity can be set for all accounts by default and also on a per-account basis, such as for accounts that are known to be temporary. To configure automatic expiration of an account following the expiration of its password (that is, after the password has expired and not been changed), run the following command, substituting NUM_DAYS and USER appropriately:

$ sudo chage -I NUM_DAYS USER

Accounts, such as temporary accounts, can also be configured to expire on an explicitly-set date with the -E option. The file /etc/default/useradd controls default settings for all newly-created accounts created with the system's normal command line utilities. number of days after a password expires until the account is permanently disabled The number of days to wait after a password expires, until the account will be permanently disabled. This will only apply to newly created accounts 35 30 35 60 90 180 Set Account Expiration Following Inactivity To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in /etc/default/useradd, substituting NUM_DAYS appropriately:

INACTIVE=NUM_DAYS

A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the useradd man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users. AC-2(2) AC-2(3) 16 17 795 Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials. CCE-TBD var_account_disable_post_pw_expiration="" grep -q ^INACTIVE /etc/default/useradd && \ sed -i "s/INACTIVE.*/INACTIVE=$var_account_disable_post_pw_expiration/g" /etc/default/useradd if ! [ $? -eq 0 ]; then echo "INACTIVE=$var_account_disable_post_pw_expiration" >> /etc/default/useradd fi To verify the INACTIVE setting, run the following command:

grep "INACTIVE" /etc/default/useradd

The output should indicate the INACTIVE configuration option is set to an appropriate integer as shown in the example below:

$ sudo grep "INACTIVE" /etc/default/useradd
INACTIVE=35

Ensure All Accounts on the System Have Unique Names Change usernames, or delete accounts, so each has a unique name. 770 804 Unique usernames allow for accountability on the system. CCE-RHEL7-CCE-TBD Run the following command to check for duplicate account names:

$ sudo pwck -qr

If there are no duplicate names, no line will be returned. Assign Expiration Date to Temporary Accounts Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts. In the event temporary or emergency accounts are required, configure the system to terminate them after a documented time period. For every temporary and emergency account, run the following command to set an expiration date on it, substituting USER and YYYY-MM-DD appropriately:

$ sudo chage -E YYYY-MM-DD USER

YYYY-MM-DD indicates the documented expiration date for the account. For U.S. Government systems, the operating system must be configured to automatically terminate these typoes of accounts after a period of 72 hours. AC-2(2) AC-2(3) 16 1682 2 If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.
CCE-27498-5 For every temporary and emergency account, run the following command to obtain its account aging and expiration information:

$ sudo chage -l USER

Verify each of these accounts has an expiration date set as documented. Protect Accounts by Configuring PAM PAM, or Pluggable Authentication Modules, is a system which implements modular authentication for Linux programs. PAM provides a flexible and configurable architecture for authentication, and it should be configured to minimize exposure to unnecessary risk. This section contains guidance on how to accomplish that.

PAM is implemented as a set of shared objects which are loaded and invoked whenever an application wishes to authenticate a user. Typically, the application must be running as root in order to take advantage of PAM, because PAM's modules often need to be able to access sensitive stores of account information, such as /etc/shadow. Traditional privileged network listeners (e.g. sshd) or SUID programs (e.g. sudo) already meet this requirement. An SUID root application, userhelper, is provided so that programs which are not SUID or privileged themselves can still take advantage of PAM.

PAM looks in the directory /etc/pam.d for application-specific configuration information. For instance, if the program login attempts to authenticate a user, then PAM's libraries follow the instructions in the file /etc/pam.d/login to determine what actions should be taken.

One very important file in /etc/pam.d is /etc/pam.d/system-auth. This file, which is included by many other PAM configuration files, defines 'default' system authentication measures. Modifying this file is a good way to make far-reaching authentication changes, for instance when implementing a centralized authentication service. Be careful when making changes to PAM's configuration files. The syntax for these files is complex, and modifications can have unexpected consequences. The default configurations shipped with applications should be sufficient for most users. Running authconfig or system-config-authentication will re-write the PAM configuration files, destroying any manually made changes and replacing them with a series of system defaults. One reference to the configuration file syntax can be found at http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/sag-configuration-file.html. remember The last n passwords for each user are saved in /etc/security/opasswd in order to force password change history and keep the user from alternating between the same password too frequently. 5 0 4 5 10 24 Set Last Logon/Access Notification To configure the system to notify users of last logon/access using pam_lastlog, add or correct the pam_lastlog settings in /etc/pam.d/postlogin to read as follows:

session     [success=1 default=ignore] pam_succeed_if.so service !~ gdm* service !~ su* quiet
session     [default=1]   pam_lastlog.so nowtmp showfailed
session     optional      pam_lastlog.so silent noupdate showfailed

53 Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators. CCE-RHEL7-CCE-TBD To ensure that last logon/access notification is configured correctly, run the following command:

$ grep pam_lastlog.so /etc/pam.d/postlogin

The output should show output showfailed. Set Password Quality Requirements The default pam_pwquality PAM module provides strength checking for passwords. It performs a number of checks, such as making sure passwords are not similar to dictionary words, are of at least a certain length, are not the previous password reversed, and are not simply a change of case from the previous password. It can also require passwords to be in certain character classes. The pam_pwquality module is the preferred way of configuring password requirements.

The pam_cracklib PAM module can also provide strength checking for passwords as the pam_pwquality module. It performs a number of checks, such as making sure passwords are not similar to dictionary words, are of at least a certain length, are not the previous password reversed, and are not simply a change of case from the previous password. It can also require passwords to be in certain character classes.

The man pages pam_pwquality(8) and pam_cracklib(8) provide information on the capabilities and configuration of each. Set Password Quality Requirements with pam_pwquality The pam_pwquality PAM module can be configured to meet requirements for a variety of policies.

For example, to configure pam_pwquality to require at least one uppercase character, lowercase character, digit, and other (special) character, make sure that pam_pwquality exists in /etc/pam.d/system-auth:

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=

If no such line exists, add one as the first line of the password section in /etc/pam.d/system-auth. Next, modify the settings in /etc/security/pwquality.conf to match the following:

difok = 4
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3

The arguments can be modified to ensure compliance with your organization's security policy. Discussion of each parameter follows. Note that the password quality requirements are not enforced for the root account for some reason. retry Number of retry attempts before erroring out 3 1 2 3 maxrepeat Maximum Number of Consecutive Repeating Characters in a Password 3 1 2 3 minlen Minimum number of characters in password 15 6 7 8 10 12 14 15 dcredit Minimum number of digits in password -1 -2 -1 0 ocredit Minimum number of other (special characters) in password -1 -2 -1 0 lcredit Minimum number of lower case in password -1 -2 -1 0 ucredit Minimum number of upper case in password -1 -2 -1 0 difok Minimum number of characters not present in old password Keep this high for short passwords 15 2 3 4 5 15 minclass Minimum number of categories of characters that must exist in a password 3 1 2 3 4 fail_deny Number of failed login attempts before account lockout 3 3 5 6 10 fail_unlock_time Seconds before automatic unlocking after excessive failed logins 604800 900 1800 3600 86400 604800 fail_interval Interval for counting failed login attempts before account lockout 900 900 1800 3600 86400 100000000 Set Password Retry Prompts Permitted Per-Session To configure the number of retry prompts that are permitted per-session:

Edit the pam_pwquality.so statement in /etc/pam.d/system-auth to show retry=, or a lower value if site policy is more restrictive.

The DoD requirement is a maximum of 3 prompts per session. IA-5(c) Test attestation on 20140925 by swells Setting the password retry prompts that are permitted on a per-session basis to a low value requires some software, such as SSH, to re-connect. This can slow down and draw additional attention to some types of password-guessing attacks. Note that this is different from account lockout, which is provided by the pam_faillock module. CCE-27131-2 var_password_pam_retry="" if grep -q "retry=" /etc/pam.d/system-auth; then sed -i --follow-symlink "s/\(retry *= *\).*/\1$var_password_pam_retry/" /etc/pam.d/system-auth else sed -i --follow-symlink "/pam_pwquality.so/ s/$/ retry=$var_password_pam_retry/" /etc/pam.d/system-auth fi To check how many retry attempts are permitted on a per-session basis, run the following command:

$ grep pam_pwquality /etc/pam.d/system-auth

The retry parameter will indicate how many attempts are permitted. The DoD required value is less than or equal to 3. This would appear as retry=3, or a lower value. Set Password to Maximum of Three Consecutive Repeating Characters The pam_pwquality module's maxrepeat parameter controls requirements for consecutive repeating characters. When set to a positive number, it will reject passwords which contain more than that number of consecutive characters. Modify the maxrepeat setting in /etc/security/pwquality.conf to prevent a run of ( + 1) or more identical characters. IA-5(c) 366 Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks. CCE-RHEL7-CCE-TBD var_password_pam_maxrepeat="" if egrep -q ^maxrepeat[[:space:]]*=[[:space:]]*[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(maxrepeat *= *\).*/\1$var_password_pam_maxrepeat/" /etc/security/pwquality.conf else sed -i "/\(maxrepeat *= *\).*/a maxrepeat = $var_password_pam_maxrepeat" /etc/security/pwquality.conf fi To check the maximum value for consecutive repeating characters, run the following command:

$ grep maxrepeat /etc/security/pwquality.conf

Look for the value of the maxrepeat parameter. The DoD requirement is 3 which would appear as maxrepeat = 3. Set Password Strength Minimum Digit Characters The pam_pwquality module's dcredit parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_pwquality will grant +1 additional length credit for each digit. Modify the dcredit setting in /etc/security/pwquality.conf to require the use of a digit in passwords. IA-5(b) IA-5(c) 194 194 71 Test attestation on 20121024 by DS Requiring digits makes password guessing attacks more difficult by ensuring a larger search space. CCE-27163-5 var_password_pam_dcredit="" if egrep -q ^dcredit[[:space:]]*=[[:space:]]*[-]?[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(dcredit *= *\).*/\1$var_password_pam_dcredit/" /etc/security/pwquality.conf else sed -i "/\(dcredit *= *\).*/a dcredit = $var_password_pam_dcredit" /etc/security/pwquality.conf fi To check how many digits are required in a password, run the following command:

$ grep dcredit /etc/security/pwquality.conf

The dcredit parameter (as a negative number) will indicate how many digits are required. The DoD requires at least one digit in a password. This would appear as dcredit = -1. Set Password Minimum Length The pam_pwquality module's minlen parameter controls requirements for minimum characters required in a password. Add minlen= after pam_pwquality to set minimum password length requirements. IA-5(1)(a) 205 78 Test attestation on 20140928 by swells Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password. CCE-26615-5 var_password_pam_minlen="" if egrep -q ^minlen[[:space:]]*=[[:space:]]*[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(minlen *= *\).*/\1$var_password_pam_minlen/" /etc/security/pwquality.conf else sed -i "/\(minlen *= *\).*/a minlen = $var_password_pam_minlen" /etc/security/pwquality.conf fi To check how many characters are required in a password, run the following command:

$ grep minlen /etc/security/pwquality.conf

Your output should contain minlen = Set Password Strength Minimum Uppercase Characters The pam_pwquality module's ucredit= parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_pwquality will grant +1 additional length credit for each uppercase character. Modify the ucredit setting in /etc/security/pwquality.conf to require the use of an uppercase character in passwords. IA-5(b) IA-5(c) IA-5(1)(a) 192 69 Test attestation on 20121024 by DS Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space. CCE-26988-6 var_password_pam_ucredit="" if egrep -q ^ucredit[[:space:]]*=[[:space:]]*[-]?[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(ucredit *= *\).*/\1$var_password_pam_ucredit/" /etc/security/pwquality.conf else sed -i "/\(ucredit *= *\).*/a ucredit = $var_password_pam_ucredit" /etc/security/pwquality.conf fi To check how many uppercase characters are required in a password, run the following command:

$ grep ucredit /etc/security/pwquality.conf

The ucredit parameter (as a negative number) will indicate how many uppercase characters are required. The DoD and FISMA require at least one uppercase character in a password. This would appear as ucredit = -1. Set Password Strength Minimum Special Characters The pam_pwquality module's ocredit= parameter controls requirements for usage of special (or "other") characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_pwquality will grant +1 additional length credit for each special character. Modify the ocredit setting in /etc/security/pwquality.conf to require use of a special character in passwords. IA-5(b) IA-5(c) IA-5(1)(a) 1619 266 Test attestation on 20121024 by DS Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space. CCE-27151-0 var_password_pam_ocredit="" if egrep -q ^ocredit[[:space:]]*=[[:space:]]*[-]?[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(ocredit *= *\).*/\1$var_password_pam_ocredit/" /etc/security/pwquality.conf else sed -i "/\(ocredit *= *\).*/a ocredit = $var_password_pam_ocredit" /etc/security/pwquality.conf fi To check how many special characters are required in a password, run the following command:

$ grep ocredit /etc/security/pwquality.conf

The ocredit parameter (as a negative number) will indicate how many special characters are required. The DoD and FISMA require at least one special character in a password. This would appear as ocredit = -1. Set Password Strength Minimum Lowercase Characters The pam_pwquality module's lcredit parameter controls requirements for usage of lowercase letters in a password. When set to a negative number, any password will be required to contain that many lowercase characters. When set to a positive number, pam_pwquality will grant +1 additional length credit for each lowercase character. Modify the lcredit setting in /etc/security/pwquality.conf to require the use of a lowercase character in passwords. IA-5(b) IA-5(c) IA-5(1)(a) 193 70 Test attestation on 20121024 by DS Requiring a minimum number of lowercase characters makes password guessing attacks more difficult by ensuring a larger search space. CCE-27111-4 var_password_pam_lcredit="" if egrep -q ^lcredit[[:space:]]*=[[:space:]]*[-]?[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(lcredit *= *\).*/\1$var_password_pam_lcredit/" /etc/security/pwquality.conf else sed -i "/\(lcredit *= *\).*/a lcredit = $var_password_pam_lcredit" /etc/security/pwquality.conf fi To check how many lowercase characters are required in a password, run the following command:

$ grep lcredit /etc/security/pwquality.conf

The lcredit parameter (as a negative number) will indicate how many special characters are required. The DoD and FISMA require at least one lowercase character in a password. This would appear as lcredit = -1. Set Password Strength Minimum Different Characters The pam_pwquality module's difok parameter controls requirements for usage of different characters during a password change. Modify the difok setting in /etc/security/pwquality.conf to require differing characters when changing passwords. The DoD requirement is 4. IA-5(b) IA-5(c) IA-5(1)(b) 195 72 Test attestation on 20121024 by DS Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note that passwords which are changed on compromised systems will still be compromised, however. CCE-26631-2 var_password_pam_difok="" if egrep -q ^difok[[:space:]]*=[[:space:]]*[-]?[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(difok *= *\).*/\1$var_password_pam_difok/" /etc/security/pwquality.conf else sed -i "/\(difok *= *\).*/a difok = $var_password_pam_difok" /etc/security/pwquality.conf fi To check how many characters must differ during a password change, run the following command:

$ grep difok /etc/security/pwquality.conf

The difok parameter will indicate how many characters must differ. The DoD requires four characters differ during a password change. This would appear as difok = 4. Set Password Strength Minimum Different Categories The pam_pwquality module's minclass parameter controls requirements for usage of different character classes, or types, of character that must exist in a password before it is considered valid. For example, setting this value to three (3) requires that any password must have characters from at least three different categories in order to be approved. The default value is zero (0), meaning there are no required classes. There are four categories available:


* Upper-case characters
* Lower-case characters
* Digits
* Special characters (for example, punctuation)

Modify the minclass setting in /etc/security/pwquality.conf entry to require differing categories of characters when changing passwords. The minimum requirement is 3. Test attestation on 20140626 by JL Requiring a minimum number of character categories makes password guessing attacks more difficult by ensuring a larger search space. CCE-27115-5 var_password_pam_minclass="" if egrep -q ^minclass[[:space:]]*=[[:space:]]*[[:digit:]]+ /etc/security/pwquality.conf; then sed -i "s/^\(minclass *= *\).*/\1$var_password_pam_minclass/" /etc/security/pwquality.conf else sed -i "/\(minclass *= *\).*/a minclass = $var_password_pam_minclass" /etc/security/pwquality.conf fi To check how many categories of characters must be used in password during a password change, run the following command:

$ grep minclass /etc/security/pwquality.conf

The minclass parameter will indicate how many character classes must be used. If the requirement was for the password to contain characters from three different categories, then this would appear as minclass = 3. Set Lockouts for Failed Password Attempts The pam_faillock PAM module provides the capability to lock out user accounts after a number of failed login attempts. Its documentation is available in /usr/share/doc/pam-VERSION/txts/README.pam_faillock.

Locking out user accounts presents the risk of a denial-of-service attack. The lockout policy must weigh whether the risk of such a denial-of-service attack outweighs the benefits of thwarting password guessing attacks. Set Deny For Failed Password Attempts To configure the system to lock out accounts after a number of incorrect login attempts using pam_faillock.so, modify the content of both /etc/pam.d/system-auth and /etc/pam.d/password-auth as follows:

    add the following line immediately before the pam_unix.so statement in the AUTH section:

    auth required pam_faillock.so preauth silent deny= unlock_time= fail_interval=

    add the following line immediately after the pam_unix.so statement in the AUTH section:

    auth [default=die] pam_faillock.so authfail deny= unlock_time= fail_interval=

    add the following line immediately before the pam_unix.so statement in the ACCOUNT section:

    account required pam_faillock.so

AC-7(a) 44 21 Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. CCE-26891-2 var_accounts_passwords_pam_faillock_deny="" AUTH_FILES[0]="/etc/pam.d/system-auth" AUTH_FILES[1]="/etc/pam.d/password-auth" for pamFile in "${AUTH_FILES[@]}" do # pam_faillock.so already present? if grep -q "^auth.*pam_faillock.so.*" $pamFile; then # pam_faillock.so present, deny directive present? if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*deny=" $pamFile; then # both pam_faillock.so & deny present, just correct deny directive value sed -i --follow-symlink "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile sed -i --follow-symlink "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile # pam_faillock.so present, but deny directive not yet else # append correct deny value to appropriate places sed -i --follow-symlink "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile sed -i --follow-symlink "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile fi # pam_faillock.so not present yet else # insert pam_faillock.so preauth & authfail rows with proper value of the 'deny' option sed -i --follow-symlink "/^auth.*sufficient.*pam_unix.so.*/i auth required pam_faillock.so preauth silent deny=$var_accounts_passwords_pam_faillock_deny" $pamFile sed -i --follow-symlink "/^auth.*sufficient.*pam_unix.so.*/a auth [default=die] pam_faillock.so authfail deny=$var_accounts_passwords_pam_faillock_deny" $pamFile sed -i --follow-symlink "/^account.*required.*pam_unix.so/i account required pam_faillock.so" $pamFile fi done To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth

The output should show deny=. Set Lockout Time For Failed Password Attempts To configure the system to lock out accounts after a number of incorrect login attempts and require an administrator to unlock the account using pam_faillock.so, modify the content of both /etc/pam.d/system-auth and /etc/pam.d/password-auth as follows:

    add the following line immediately before the pam_unix.so statement in the AUTH section:

    auth required pam_faillock.so preauth silent deny= unlock_time= fail_interval=

    add the following line immediately after the pam_unix.so statement in the AUTH section:

    auth [default=die] pam_faillock.so authfail deny= unlock_time= fail_interval=

    add the following line immediately before the pam_unix.so statement in the ACCOUNT section:

    account required pam_faillock.so

AC-7(b) 47 Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. Ensuring that an administrator is involved in unlocking locked accounts draws appropriate attention to such situations. CCE-26884-7 To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth

The output should show unlock_time=<some-large-number>. Set Interval For Counting Failed Password Attempts Utilizing pam_faillock.so, the fail_interval directive configures the system to lock out accounts after a number of incorrect login attempts. Modify the content of both /etc/pam.d/system-auth and /etc/pam.d/password-auth as follows:

    add the following line immediately before the pam_unix.so statement in the AUTH section:

    auth required pam_faillock.so preauth silent deny= unlock_time= fail_interval=

    add the following line immediately after the pam_unix.so statement in the AUTH section:

    auth [default=die] pam_faillock.so authfail deny= unlock_time= fail_interval=

    add the following line immediately before the pam_unix.so statement in the ACCOUNT section:

    account required pam_faillock.so

AC-7(a) 44 21 Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks. CCE-26763-3 To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

For each file, the output should show fail_interval=<interval-in-seconds> where interval-in-seconds is or greater. If the fail_interval parameter is not set, the default setting of 900 seconds is acceptable. Limit Password Reuse Do not allow users to reuse recent passwords. This can be accomplished by using the remember option for the pam_unix PAM module. In the file /etc/pam.d/system-auth, append remember= to the line which refers to the pam_unix.so module, as shown:

password sufficient pam_unix.so existing_options remember=

The DoD STIG requirement is 5 passwords. IA-5(f) IA-5(1)(e) 200 77 Test attestation on 20121024 by DS Preventing re-use of previous passwords helps ensure that a compromised password is not re-used by a user. CCE-26923-3 var_password_pam_unix_remember="" if grep -q "remember=" /etc/pam.d/system-auth; then sed -i --follow-symlink "s/\(remember *= *\).*/\1$var_password_pam_unix_remember/" /etc/pam.d/system-auth else sed -i --follow-symlink "/^password[[:space:]]\+sufficient[[:space:]]\+pam_unix.so/ s/$/ remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth fi To verify the password reuse setting is compliant, run the following command:

$ grep remember /etc/pam.d/system-auth

The output should show the following at the end of the line:

remember=

Set Password Hashing Algorithm The system's default algorithm for storing password hashes in /etc/shadow is SHA-512. This can be configured in several locations. Set Password Hashing Algorithm in /etc/pam.d/system-auth In /etc/pam.d/system-auth, the password section of the file controls which PAM modules execute during a password change. Set the pam_unix.so module in the password section to include the argument sha512, as shown below:

password    sufficient    pam_unix.so sha512 other arguments...

This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default. IA-5(b) IA-5(c) IA-5(1)(c) IA-7 Test attestation on 20121024 by DS Using a stronger hashing algorithm makes password cracking attacks more difficult. CCE-27104-9 if ! grep -q "^password.*sufficient.*pam_unix.so.*sha512" /etc/pam.d/system-auth; then sed -i --follow-symlink "/^password.*sufficient.*pam_unix.so/ s/$/ sha512/" /etc/pam.d/system-auth fi Inspect the password section of /etc/pam.d/system-auth and ensure that the pam_unix.so module includes the argument sha512:

$ grep sha512 /etc/pam.d/system-auth

Set Password Hashing Algorithm in /etc/login.defs In /etc/login.defs, add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm:

ENCRYPT_METHOD SHA512

IA-5(b) IA-5(c) IA-5(1)(c) IA-7 Test attestation on 20121024 by DS Using a stronger hashing algorithm makes password cracking attacks more difficult. CCE-27124-7 if grep --silent ^ENCRYPT_METHOD /etc/login.defs ; then sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' /etc/login.defs else echo "" >> /etc/login.defs echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs fi Inspect /etc/login.defs and ensure the following line appears:

ENCRYPT_METHOD SHA512

Set Password Hashing Algorithm in /etc/libuser.conf In /etc/libuser.conf, add or correct the following line in its [defaults] section to ensure the system will use the SHA-512 algorithm for password hashing:

crypt_style = sha512

IA-5(b) IA-5(c) IA-5(1)(c) IA-7 Test attestation on 20121026 by DS Using a stronger hashing algorithm makes password cracking attacks more difficult. CCE-27053-8 Inspect /etc/libuser.conf and ensure the following line appears in the [default] section:

crypt_style = sha512

Secure Session Configuration Files for Login Accounts When a user logs into a Unix account, the system configures the user's session by reading a number of files. Many of these files are located in the user's home directory, and may have weak permissions as a result of user error or misconfiguration. If an attacker can modify or even read certain types of account configuration information, they can often gain full access to the affected user's account. Therefore, it is important to test and correct configuration file permissions for interactive accounts, particularly those of privileged users such as root or system administrators. Maximum concurrent login sessions Maximum number of concurrent sessions by a user 1 1 3 5 10 15 20 Limit the Number of Concurrent Login Sessions Allowed Per User Limiting the number of allowed users and sessions per user can limit risks related to Denial of Service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. The DoD requirement is 10. To set the number of concurrent sessions per user add the following line in /etc/security/limits.conf:

* hard maxlogins 

AC-10 54 27 Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions. CCE-27081-9 var_accounts_max_concurrent_login_sessions="" echo "* hard maxlogins $var_accounts_max_concurrent_login_sessions" >> /etc/security/limits.conf Run the following command to ensure the maxlogins value is configured for all users on the system:

# grep "maxlogins" /etc/security/limits.conf

You should receive output similar to the following:

*		hard	maxlogins	

Ensure that No Dangerous Directories Exist in Root's Path The active path of the root account can be obtained by starting a new root shell and running:

# echo $PATH

This will produce a colon-separated list of directories in the path.

Certain path elements could be considered dangerous, as they could lead to root executing unknown or untrusted programs, which could contain malicious code. Since root may sometimes work inside untrusted directories, the . character, which represents the current directory, should never be in the root path, nor should any directory which can be written to by an unprivileged or semi-privileged (system) user.

It is a good practice for administrators to always execute privileged commands by typing the full path to the command. Ensure that Root's Path Does Not Include Relative Paths or Null Directories Ensure that none of the directories in root's path is equal to a single . character, or that it contains any instances that lead to relative path traversal, such as .. or beginning a path without the slash (/) character. Also ensure that there are no "empty" elements in the path, such as in these examples:

PATH=:/bin
PATH=/bin:
PATH=/bin::/sbin

These empty elements have the same effect as a single . character. Including these entries increases the risk that root could execute code from an untrusted location. CCE-RHEL7-CCE-TBD Ensure that Root's Path Does Not Include World or Group-Writable Directories For each element in root's path, run:

# ls -ld DIR

and ensure that write permissions are disabled for group and other. Such entries increase the risk that root could execute code provided by unprivileged users, and potentially malicious code. CCE-RHEL7-CCE-TBD To ensure write permissions are disabled for group and other for each element in root's path, run the following command:

# ls -ld DIR

Ensure that User Home Directories are not Group-Writable or World-Readable For each human user of the system, view the permissions of the user's home directory:

# ls -ld /home/USER

Ensure that the directory is not group-writable and that it is not world-readable. If necessary, repair the permissions:

# chmod g-w /home/USER
# chmod o-rwx /home/USER

This action may involve modifying user home directories. Notify your user community, and solicit input if appropriate, before making this type of change. AC-6 User home directories contain many configuration files which affect the behavior of a user's account. No user should ever have write permission to another user's home directory. Group shared directories can be configured in sub-directories or elsewhere in the filesystem if they are needed. Typically, user home directories should not be world-readable, as it would disclose file names to other users. If a subset of users need read access to one another's home directories, this can be provided using groups or ACLs. CCE-RHEL7-CCE-TBD To ensure the user home directory is not group-writable or world-readable, run the following:

# ls -ld /home/USER

Ensure that Users Have Sensible Umask Values The umask setting controls the default permissions for the creation of new files. With a default umask setting of 077, files and directories created by users will not be readable by any other user on the system. Users who wish to make specific files group- or world-readable can accomplish this by using the chmod command. Additionally, users can make all their files readable to their group by default by setting a umask of 027 in their shell configuration files. If default per-user groups exist (that is, if every user has a default group whose name is the same as that user's username and whose only member is the user), then it may even be safe for users to select a umask of 007, making it very easy to intentionally share files with groups of which the user is a member.

Sensible umask Enter default user umask 027 007 022 027 077 Ensure the Default Bash Umask is Set Correctly To ensure the default umask for users of the Bash shell is set properly, add or correct the umask setting in /etc/bashrc to read as follows:

umask 077

SA-8 366 Test attestation on 20140912 by JL The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read or written to by unauthorized users. CCE-RHEL7-CCE-TBD var_accounts_user_umask="" grep -q umask /etc/bashrc && \ sed -i "s/umask.*/umask $var_accounts_user_umask/g" /etc/bashrc if ! [ $? -eq 0 ]; then echo "umask $var_accounts_user_umask" >> /etc/bashrc fi Verify the umask setting is configured correctly in the /etc/bashrc file by running the following command:

# grep "umask" /etc/bashrc

All output must show the value of umask set to 077, as shown below:

# grep "umask" /etc/bashrc
umask 077
umask 077

Ensure the Default C Shell Umask is Set Correctly To ensure the default umask for users of the C shell is set properly, add or correct the umask setting in /etc/csh.cshrc to read as follows:

umask 077

SA-8 366 Test attestation on 20140912 by JL The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read or written to by unauthorized users. CCE-RHEL7-CCE-TBD var_accounts_user_umask="" grep -q umask /etc/csh.cshrc && \ sed -i "s/umask.*/umask $var_accounts_user_umask/g" /etc/csh.cshrc if ! [ $? -eq 0 ]; then echo "umask $var_accounts_user_umask" >> /etc/csh.cshrc fi Verify the umask setting is configured correctly in the /etc/csh.cshrc file by running the following command:

# grep "umask" /etc/csh.cshrc

All output must show the value of umask set to 077, as shown in the below:

# grep "umask" /etc/csh.cshrc
umask 077

Ensure the Default Umask is Set Correctly in /etc/profile To ensure the default umask controlled by /etc/profile is set properly, add or correct the umask setting in /etc/profile to read as follows:

umask 077

SA-8 366 Test attestation on 20120929 by swells The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read or written to by unauthorized users. CCE-RHEL7-CCE-TBD var_accounts_user_umask="" grep -q umask /etc/profile && \ sed -i "s/umask.*/umask $var_accounts_user_umask/g" /etc/profile if ! [ $? -eq 0 ]; then echo "umask $var_accounts_user_umask" >> /etc/profile fi Verify the umask setting is configured correctly in the /etc/profile file by running the following command:

# grep "umask" /etc/profile

All output must show the value of umask set to 077, as shown in the below:

# grep "umask" /etc/profile
umask 077

Ensure the Default Umask is Set Correctly in login.defs To ensure the default umask controlled by /etc/login.defs is set properly, add or correct the UMASK setting in /etc/login.defs to read as follows:

UMASK 077

SA-8 366 Test attestation on 20140912 by JL The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and written to by unauthorized users. CCE-RHEL7-CCE-TBD var_accounts_user_umask="" grep -q UMASK /etc/login.defs && \ sed -i "s/UMASK.*/UMASK $var_accounts_user_umask/g" /etc/login.defs if ! [ $? -eq 0 ]; then echo "UMASK $var_accounts_user_umask" >> /etc/login.defs fi Verify the UMASK setting is configured correctly in the /etc/login.defs file by running the following command:

# grep -i "UMASK" /etc/login.defs

All output must show the value of umask set to 077, as shown in the below:

# grep -i "UMASK" /etc/login.defs
umask 077

Protect Physical Console Access It is impossible to fully protect a system from an attacker with physical access, so securing the space in which the system is located should be considered a necessary step. However, there are some steps which, if taken, make it more difficult for an attacker to quickly or undetectably modify a system from its console. Set Boot Loader Password During the boot process, the boot loader is responsible for starting the execution of the kernel and passing options to it. The boot loader allows for the selection of different kernels - possibly on different partitions or media. The default RHEL boot loader for x86 systems is called GRUB2. Options it can pass to the kernel include single-user mode, which provides root access without any authentication, and the ability to disable SELinux. To prevent local users from modifying the boot parameters and endangering security, protect the boot loader configuration with a password and ensure its configuration file's permissions are set properly. Verify /boot/grub2/grub.cfg User Ownership The file /boot/grub2/grub.cfg should be owned by the root user to prevent destruction or modification of the file. To properly set the owner of /boot/grub2/grub.cfg, run the command:

$ sudo chown root /boot/grub2/grub.cfg

Test attestation on 20121026 by DS Only root should be able to modify important boot parameters. CCE-26860-7 chown root /boot/grub2/grub.cfg To check the ownership of /boot/grub2/grub.cfg, run the command:

$ ls -lL /boot/grub2/grub.cfg

If properly configured, the output should indicate the following owner: root Verify /boot/grub2/grub.cfg Group Ownership The file /boot/grub2/grub.cfg should be group-owned by the root group to prevent destruction or modification of the file. To properly set the group owner of /boot/grub2/grub.cfg, run the command:

$ sudo chgrp root xsl:value-of select="@file"/> 

Test attestation on 20121026 by DS The root group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway. CCE-26812-8 chgrp root /boot/grub2/grub.cfg To check the group ownership of /boot/grub2/grub.cfg, run the command:

$ ls -lL /boot/grub2/grub.cfg

If properly configured, the output should indicate the following group-owner. root Verify /boot/grub2/grub.cfg Permissions File permissions for /boot/grub2/grub.cfg should be set to 600. To properly set the permissions of /boot/grub2/grub.cfg, run the command:

$ sudo chmod 600 /boot/grub2/grub.cfg

Test attestation on 20121026 by DS Proper permissions ensure that only the root user can modify important boot parameters. CCE-27054-6 chmod 600 /boot/grub2/grub.cfg To check the permissions of /boot/grub2/grub.cfg, run the command:

$ sudo ls -lL /boot/grub2/grub.cfg

If properly configured, the output should indicate the following permissions: -rw------- Set Boot Loader Password The grub2 boot loader should have a superuser account and password protection enabled to protect boot-time settings.

To do so, select a superuser account and password and add them into the appropriate grub2 configuration file(s) under /etc/grub.d. Since plaintext passwords are a security risk, generate a hash for the pasword by running the following command:

$ grub2-mkpasswd-pbkdf2

When prompted, enter the password that was selected and insert the returned password hash into the appropriate grub2 configuration file(s) under /etc/grub.d immediately after the superuser account. (Use the output from grub2-mkpasswd-pbkdf2 as the value of password-hash):

password_pbkdf2 superusers-account password-hash

NOTE: It is recommended not to use common administrator account names like root, admin, or administrator for the grub2 superuser account.
To meet FISMA Moderate, the bootloader superuser account and password MUST differ from the root account and password. Once the superuser account and password have been added, update the grub.cfg file by running:

grub2-mkconfig -o /boot/grub2/grub.cfg

NOTE: Do NOT manually add the superuser account and password to the grub.cfg file as the grub2-mkconfig command overwrites this file. IA-2(1) IA-5(e) AC-3 Test attestation on 20121026 by DS Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode. For more information on how to configure the grub2 superuser account and password, please refer to

    https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/sec-GRUB_2_Password_Protection.html
    . 

CCE-26809-4 To verify the boot loader superuser account and superuser account password have been set, and the password encrypted, run the following command:

sudo grep -A1 "superusers\|password" /etc/grub2.cfg

The output should show the following:

set superusers="superusers-account"
password_pbkdf2 superusers-account password-hash

Require Authentication for Single User Mode Single-user mode is intended as a system recovery method, providing a single user root access to the system by providing a boot option at startup. By default, no authentication is performed if single-user mode is selected.

By default, single-user mode is protected by requiring a password and is set in /usr/lib/systemd/system/rescue.service. IA-2(1) AC-3 213 Test attestation on 20121024 by DS This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password. CCE-27170-0 grep -q ^SINGLE /etc/sysconfig/init && \ sed -i "s/SINGLE.*/SINGLE=\/sbin\/sulogin/g" /etc/sysconfig/init if ! [ $? -eq 0 ]; then echo "SINGLE=/sbin/sulogin" >> /etc/sysconfig/init fi To check if authentication is required for single-user mode, run the following command:

$ grep sulogin /usr/lib/systemd/system/rescue.service

The output should be similar to the following, and the line must begin with ExecStart and /sbin/sulogin:

ExecStart=-/sbin/sulogin

Disable Ctrl-Alt-Del Reboot Activation By default, the system includes the following line in /etc/init/control-alt-delete.conf to reboot the system when the Ctrl-Alt-Del key sequence is pressed:

exec /sbin/shutdown -r now "Control-Alt-Delete pressed"


To configure the system to log a message instead of rebooting the system, alter that line to read as follows:

exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"

A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Del sequence is reduced because the user will be prompted before any action is taken. CCE-RHEL7-CCE-TBD # The process to disable ctrl+alt+del has changed in RHEL7. # Reference: https://access.redhat.com/solutions/1123873 ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target To ensure the system is configured to log a message instead of rebooting the system when Ctrl-Alt-Del is pressed, ensure the following line is in /etc/init/control-alt-delete.conf:

exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"

Disable Interactive Boot To disable the ability for users to perform interactive startups, edit the file /etc/sysconfig/init. Add or correct the line:

PROMPT=no

The PROMPT option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot. SC-2 AC-3 213 Test attestation on 20121024 by DS Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security. CCE-RHEL7-CCE-TBD grep -q ^PROMPT /etc/sysconfig/init && \ sed -i "s/PROMPT.*/PROMPT=no/g" /etc/sysconfig/init if ! [ $? -eq 0 ]; then echo "PROMPT=no" >> /etc/sysconfig/init fi To check whether interactive boot is disabled, run the following command:

$ grep PROMPT /etc/sysconfig/init

If interactive boot is disabled, the output will show:

PROMPT=no

Configure Screen Locking When a user must temporarily leave an account logged-in, screen locking should be employed to prevent passersby from abusing the account. User education and training is particularly important for screen locking to be effective, and policies can be implemented to reinforce this.

Automatic screen locking is only meant as a safeguard for those cases where a user forgot to lock the screen. Configure GUI Screen Locking In the default GNOME3 desktop, the screen can be locked by selecting the user name in the far right corner of the main panel and selecting Lock.

The following sections detail commands to enforce idle activation of the screensaver, screen locking, a blank-screen screensaver, and an idle activation time.

Because users should be trained to lock the screen when they step away from the computer, the automatic locking feature is only meant as a backup.

The root account can be screen-locked; however, the root account should never be used to log into an X Windows environment and should only be used to for direct login via console in emergency circumstances.

For more information about enforcing preferences in the GNOME3 environment using the DConf configuration system, see http://wiki.gnome.org/dconf and the man page dconf(1). For Red Hat specific information on configuring DConf settings, see https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/Desktop_Migration_and_Administration_Guide/part-Configuration_and_Administration.html Inactivity timeout Choose allowed duration of inactive SSH connections, shells, and X sessions 900 300 600 900 Set GNOME3 Screensaver Inactivity Timeout To set the idle time-out value for inactivity in the GNOME3 desktop to 5 minutes (in seconds), the idle-delay setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory and locked in /etc/dconf/db/local.d/locks directory to prevent user modification. After the settings have been set, run dconf update. AC-11(a) 57 Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby. CCE-RHEL7-CCE-TBD To check the current idle time-out value, run the following command:

$ gsettings get org.gnome.desktop.session idle-delay

If properly configured, the output should be 300. To ensure that users cannot change the screensaver inactivity timeout setting, run the following:

$ grep idle-delay /etc/dconf/db/local.d/locks/*

If properly configured, the output should be /org/gnome/desktop/session/idle-delay Enable GNOME3 Screensaver Idle Activation To activate the screensaver in the GNOME3 desktop after a period of inactivity, the idle-activation-enabled setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory and locked in /etc/dconf/db/local.d/locks directory to prevent user modification. After the settings have been set, run dconf update. AC-11(a) 57 Enabling idle activation of the screensaver ensures the screensaver will be activated after the idle delay. Applications requiring continuous, real-time screen display (such as network management products) require the login session does not have administrator rights and the display station is located in a controlled-access area. CCE-RHEL7-CCE-TBD To check the screensaver mandatory use status, run the following command:

$ gsettings get org.gnome.desktop.screensaver idle-activation-enabled

If properly configured, the output should be true. To ensure that users cannot disable the screensaver idle inactivity setting, run the following:

$ grep idle-activation-enabled /etc/dconf/db/local.d/locks/*

If properly configured, the output should be /org/gnome/desktop/screensaver/idle-activation-enabled Enable GNOME3 Screensaver Lock After Idle Period To activate locking of the screensaver in the GNOME3 desktop when it is activated, the lock-enabled and lock-delay setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory and locked in /etc/dconf/db/local.d/locks directory to prevent user modification. After the settings have been set, run dconf update. AC-11(a) 57 Enabling the activation of the screen lock after an idle period ensures password entry will be required in order to access the system, preventing access by passersby. CCE-RHEL7-CCE-TBD To check the status of the idle screen lock activation, run the following command:

$ gsettings get org.gnome.desktop.screensaver lock-enabled

If properly configured, the output should be true. To check that the screen locks when activated, run the following command:

$ gsettings get org.gnome.desktop.screensaver lock-delay

If properly configured, the output should be 0. To ensure that users cannot change how long until the the screensaver locks, run the following:

$ grep 'lock-enabled\|lock-delay' /etc/dconf/db/local.d/locks/*

If properly configured, the output for lock-enabled should be /org/gnome/desktop/screensaver/lock-enabled If properly configured, the output for lock-delay should be /org/gnome/desktop/screensaver/lock-delay Implement Blank Screensaver To set the screensaver mode in the GNOME3 desktop to a blank screen, the picture-uri setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory and locked in /etc/dconf/db/local.d/locks directory to prevent user modification. After the settings have been set, run dconf update. AC-11(b) 60 Setting the screensaver mode to blank-only conceals the contents of the display from passersby. CCE-RHEL7-CCE-TBD To ensure the screensaver is configured to be blank, run the following command:

$ gsettings get org.gnome.desktop.screensaver picture-uri

If properly configured, the output should be ''. To ensure that users cannot set the screensaver background, run the following:

$ grep picture-uri /etc/dconf/db/local.d/locks/*

If properly configured, the output should be /org/gnome/desktop/screensaver/picture-uri Configure Console Screen Locking A console screen locking mechanism is provided in the screen package, which is not installed by default. Install the screen Package To enable console screen locking, install the screen package:

$ sudo yum install screen

Instruct users to begin new terminal sessions with the following command:

$ screen

The console can now be locked with the following key combination:

ctrl+a x

58 Test attestation on 20121026 by DS Installing screen ensures a console locking capability is available for users who may need to suspend console logins. CCE-RHEL7-CCE-TBD yum -y install screen Run the following command to determine if the screen package is installed:

$ rpm -q screen

Hardware Tokens for Authentication The use of hardware tokens such as smart cards for system login provides stronger, two-factor authentication than using a username and password. In Red Hat Enterprise Linux servers and workstations, hardware token login is not enabled by default and must be enabled in the system settings. Enable Smart Card Login To enable smart card authentication, consult the documentation at:

    https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Managing_Smart_Cards/enabling-smart-card-login.html

For guidance on enabling SSH to authenticate against a Common Access Card (CAC), consult documentation at:

    https://access.redhat.com/solutions/82273

765 766 767 768 771 772 884 Smart card login provides two-factor authentication stronger than that provided by a username and password combination. Smart cards leverage PKI (public key infrastructure) in order to provide and verify credentials. CCE-RHEL7-CCE-TBD Interview the SA to determine if all accounts not exempted by policy are using CAC authentication. For DoD systems, the following systems and accounts are exempt from using smart card (CAC) authentication:

    SIPRNET systems
    Standalone systems
    Application accounts
    Temporary employee accounts, such as students or interns, who cannot easily receive a CAC or PIV
    Operational tactical locations that are not collocated with RAPIDS workstations to issue CAC or ALT
    Test systems, such as those with an Interim Approval to Test (IATT) and use a separate VPN, firewall, or security measure preventing access to network and system components from outside the protection boundary documented in the IATT.

Warning Banners for System Accesses Each system should expose as little information about itself as possible.

System banners, which are typically displayed just before a login prompt, give out information about the service or the host's operating system. This might include the distribution name and the system kernel version, and the particular version of a network service. This information can assist intruders in gaining access to the system as it can reveal whether the system is running vulnerable software. Most network services can be configured to limit what information is displayed.

Many organizations implement security policies that require a system banner provide notice of the system's ownership, provide warning to unauthorized users, and remind authorized users of their consent to monitoring. Login Banner Verbiage Enter an appropriate login banner for your organization. Please note that new lines must be expressed by the '\n' character and special characters like parentheses and quotation marks must be escaped with '\'. --[\s\n]+WARNING[\s\n]+--[\s\n]*This[\s\n]+system[\s\n]+is[\s\n]+for[\s\n]+the[\s\n]+use[\s\n]+of[\s\n]+authorized[\s\n]+users[\s\n]+only.[\s\n]+Individuals[\s\n]*using[\s\n]+this[\s\n]+computer[\s\n]+system[\s\n]+without[\s\n]+authority[\s\n]+or[\s\n]+in[\s\n]+excess[\s\n]+of[\s\n]+their[\s\n]*authority[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+having[\s\n]+all[\s\n]+their[\s\n]+activities[\s\n]+on[\s\n]+this[\s\n]+system[\s\n]*monitored[\s\n]+and[\s\n]+recorded[\s\n]+by[\s\n]+system[\s\n]+personnel.[\s\n]+Anyone[\s\n]+using[\s\n]+this[\s\n]*system[\s\n]+expressly[\s\n]+consents[\s\n]+to[\s\n]+such[\s\n]+monitoring[\s\n]+and[\s\n]+is[\s\n]+advised[\s\n]+that[\s\n]*if[\s\n]+such[\s\n]+monitoring[\s\n]+reveals[\s\n]+possible[\s\n]+evidence[\s\n]+of[\s\n]+criminal[\s\n]+activity[\s\n]*system[\s\n]+personal[\s\n]+may[\s\n]+provide[\s\n]+the[\s\n]+evidence[\s\n]+of[\s\n]+such[\s\n]+monitoring[\s\n]+to[\s\n]+law[\s\n]*enforcement[\s\n]+officials. You[\s\n]+are[\s\n]+accessing[\s\n]+a[\s\n]+U.S.[\s\n]+Government[\s\n]+\(USG\)[\s\n]+Information[\s\n]+System[\s\n]+\(IS\)[\s\n]+that[\s\n]+is[\s\n]+provided[\s\n]+for[\s\n]+USG-authorized[\s\n]+use[\s\n]+only.[\s\n]*By[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+\(which[\s\n]+includes[\s\n]+any[\s\n]+device[\s\n]+attached[\s\n]+to[\s\n]+this[\s\n]+IS\),[\s\n]+you[\s\n]+consent[\s\n]+to[\s\n]+the[\s\n]+following[\s\n]+conditions\:[\s\n]*-[\s\n]*The[\s\n]+USG[\s\n]+routinely[\s\n]+intercepts[\s\n]+and[\s\n]+monitors[\s\n]+communications[\s\n]+on[\s\n]+this[\s\n]+IS[\s\n]+for[\s\n]+purposes[\s\n]+including,[\s\n]+but[\s\n]+not[\s\n]+limited[\s\n]+to,[\s\n]+penetration[\s\n]+testing,[\s\n]+COMSEC[\s\n]+monitoring,[\s\n]+network[\s\n]+operations[\s\n]+and[\s\n]+defense,[\s\n]+personnel[\s\n]+misconduct[\s\n]+\(PM\),[\s\n]+law[\s\n]+enforcement[\s\n]+\(LE\),[\s\n]+and[\s\n]+counterintelligence[\s\n]+\(CI\)[\s\n]+investigations.[\s\n]*-[\s\n]*At[\s\n]+any[\s\n]+time,[\s\n]+the[\s\n]+USG[\s\n]+may[\s\n]+inspect[\s\n]+and[\s\n]+seize[\s\n]+data[\s\n]+stored[\s\n]+on[\s\n]+this[\s\n]+IS.[\s\n]*-[\s\n]*Communications[\s\n]+using,[\s\n]+or[\s\n]+data[\s\n]+stored[\s\n]+on,[\s\n]+this[\s\n]+IS[\s\n]+are[\s\n]+not[\s\n]+private,[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+routine[\s\n]+monitoring,[\s\n]+interception,[\s\n]+and[\s\n]+search,[\s\n]+and[\s\n]+may[\s\n]+be[\s\n]+disclosed[\s\n]+or[\s\n]+used[\s\n]+for[\s\n]+any[\s\n]+USG-authorized[\s\n]+purpose.[\s\n]*-[\s\n]*This[\s\n]+IS[\s\n]+includes[\s\n]+security[\s\n]+measures[\s\n]+\(e.g.,[\s\n]+authentication[\s\n]+and[\s\n]+access[\s\n]+controls\)[\s\n]+to[\s\n]+protect[\s\n]+USG[\s\n]+interests[\s\n]+--[\s\n]+not[\s\n]+for[\s\n]+your[\s\n]+personal[\s\n]+benefit[\s\n]+or[\s\n]+privacy.[\s\n]*-[\s\n]*Notwithstanding[\s\n]+the[\s\n]+above,[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+does[\s\n]+not[\s\n]+constitute[\s\n]+consent[\s\n]+to[\s\n]+PM,[\s\n]+LE[\s\n]+or[\s\n]+CI[\s\n]+investigative[\s\n]+searching[\s\n]+or[\s\n]+monitoring[\s\n]+of[\s\n]+the[\s\n]+content[\s\n]+of[\s\n]+privileged[\s\n]+communications,[\s\n]+or[\s\n]+work[\s\n]+product,[\s\n]+related[\s\n]+to[\s\n]+personal[\s\n]+representation[\s\n]+or[\s\n]+services[\s\n]+by[\s\n]+attorneys,[\s\n]+psychotherapists,[\s\n]+or[\s\n]+clergy,[\s\n]+and[\s\n]+their[\s\n]+assistants.[\s\n]+Such[\s\n]+communications[\s\n]+and[\s\n]+work[\s\n]+product[\s\n]+are[\s\n]+private[\s\n]+and[\s\n]+confidential.[\s\n]+See[\s\n]+User[\s\n]+Agreement[\s\n]+for[\s\n]+details. I\'ve[\s\n]+read[\s\n]+\&[\s\n]+consent[\s\n]+to[\s\n]+terms[\s\n]+in[\s\n]+IS[\s\n]+user[\s\n]+agreem\'t. Modify the System Login Banner To configure the system login banner:

Edit /etc/issue. Replace the default text with a message compliant with the local site policy or a legal disclaimer. The DoD required text is either:

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

OR:

I've read & consent to terms in IS user agreem't. AC-8(a) AC-8(b) AC-8(c)(1) AC-8(c)(2) AC-8(c)(3) 48 50 1384 1385 1386 1387 1388 23 228 Test attestation on 20121026 by DS An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. CCE-27303-7 login_banner_text="" # There was a regular-expression matching various banners, needs to be expanded expanded=$(echo "$login_banner_text" | sed 's/\[\\s\\n\][+*]/ /g;s/\\//g;s/[^-]- /\n\n-/g') formatted=$(echo "$expanded" | fold -sw 80) cat <<EOF >/etc/issue $formatted EOF printf "\n" >> /etc/issue To check if the system login banner is compliant, run the following command:

$ cat /etc/issue

Implement a GUI Warning Banner In the default graphical environment, users logging directly into the system are greeted with a login screen provided by the GNOME3 Display Manager (GDM). The warning banner should be displayed in this graphical environment for these users. The following sections describe how to configure the GDM login banner. Enable GNOME3 Login Warning Banner To enable displaying a login warning banner in the GNOME Display Manager's login screen, the banner-message-enable setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/gdm.d directory and locked in /etc/dconf/db/gdm.d/locks directory to prevent user modification. After the settings have been set, run dconf update. To display a banner, this setting must be enabled, and the user must be prevented from making changes. The banner text must also be set. AC-8(a) AC-8(b) AC-8(c) 48 50 23 An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. CCE-26970-4 To ensure a login warning banner is enabled, run the following:

$ grep banner-message-enable /etc/dconf/db/gdm.d/*

If properly configured, the output should be true. To ensure a login warning banner is locked and cannot be changed by a user, run the following:

$ grep banner-message-enable /etc/dconf/db/gdm.d/locks/*

If properly configured, the output should be /org/gnome/login-screen/banner-message-enable. Set the GNOME3 Login Warning Banner Text To set the text shown by the GNOME3 Display Manager in the login screen, the banner-message-text setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/gdm.d directory and locked in /etc/dconf/db/gdm.d/locks directory to prevent user modification. After the settings have been set, run dconf update. When entering a warning banner that spans several lines, remember to begin and end the string with ' and use \n for new lines. AC-8(a) AC-8(b) AC-8(c) 48 50 1384 1385 1386 1387 1388 23 An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. CCE-26892-0 To ensure the login warning banner text is properly set, run the following:

$ grep banner-message-text /etc/dconf/db/gdm.d/*

If properly configured, the proper banner text will appear. To ensure the login warning banner text is locked and cannot be changed by a user, run the following:

$ grep banner-message-enable /etc/dconf/db/gdm.d/locks/*

If properly configured, the output should be /org/gnome/login-screen/banner-message-text. Disable the GNOME3 Login User List In the default graphical environment, users logging directly into the system are greeted with a login screen that displays all known users. This functionality should be disabled.

The disable-user-list setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/gdm.d directory and locked in /etc/dconf/db/gdm.d/locks directory to prevent user modification. After the settings have been set, run dconf update. AC-23 Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to quickly enumerate known user accounts without logging in. CCE-RHEL7-CCE-TBD To ensure the user list is disabled, run the following command:

$ grep disable-user-list /etc/dconf/db/gdm.d/*

The output should be true. To ensure that users cannot enable displaying the user list, run the following:

$ grep disable-user-list /etc/dconf/db/gdm.d/locks/*

If properly configured, the output should be /org/gnome/login-screen/disable-user-list Network Configuration and Firewalls Most machines must be connected to a network of some sort, and this brings with it the substantial risk of network attack. This section discusses the security impact of decisions about networking which must be made when configuring a system.

This section also discusses firewalls, network access controls, and other network security frameworks, which allow system-level rules to be written that can limit an attackers' ability to connect to your system. These rules can specify that network traffic should be allowed or denied from certain IP addresses, hosts, and networks. The rules can also specify which of the system's network services are available to particular hosts or networks. Disable Unused Interfaces Network interfaces expand the attack surface of the system. Unused interfaces are not monitored or controlled, and should be disabled.

If the system does not require network communications but still needs to use the loopback interface, remove all files of the form ifcfg-interface except for ifcfg-lo from /etc/sysconfig/network-scripts:

$ sudo rm /etc/sysconfig/network-scripts/ifcfg-interface

If the system is a standalone machine with no need for network access or even communication over the loopback device, then disable this service. The network service can be disabled with the following command:

$ sudo systemctl disable network

Disable Zeroconf Networking Zeroconf networking allows the system to assign itself an IP address and engage in IP communication without a statically-assigned address or even a DHCP server. Automatic address assignment via Zeroconf (or DHCP) is not recommended. To disable Zeroconf automatic route assignment in the 169.254.0.0 subnet, add or correct the following line in /etc/sysconfig/network:

NOZEROCONF=yes

CM-7 Zeroconf addresses are in the network 169.254.0.0. The networking scripts add entries to the system's routing table for these addresses. Zeroconf address assignment commonly occurs when the system is configured to use DHCP but fails to receive an address assignment from the DHCP server. CCE-RHEL7-CCE-TBD echo "NOZEROCONF=yes" >> /etc/sysconfig/network Ensure System is Not Acting as a Network Sniffer The system should not be acting as a network sniffer, which can capture all traffic on the network to which it is connected. Run the following to determine if any interface is running in promiscuous mode:

$ ip link | grep PROMISC

CM-7 MA-3 If any results are returned, then a sniffing process (such as tcpdump or Wireshark) is likely to be using the interface and this should be investigated. CCE-RHEL7-CCE-TBD Kernel Parameters Which Affect Networking The sysctl utility is used to set parameters which affect the operation of the Linux kernel. Kernel parameters which affect networking and have security implications are described here. Network Parameters for Hosts Only If the system is not going to be used as a router, then setting certain kernel parameters ensure that the host will not perform routing of network traffic. Disable Kernel Parameter for Sending ICMP Redirects by Default To set the runtime status of the net.ipv4.conf.default.send_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.default.send_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.default.send_redirects = 0

AC-4 CM-7 SC-5 SC-7 1551 Test attestation on 20121024 by DS Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.default.send_redirects # sysctl -q -n -w net.ipv4.conf.default.send_redirects=0 # # If net.ipv4.conf.default.send_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.default.send_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.default.send_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.default.send_redirects.*/net.ipv4.conf.default.send_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.default.send_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.default.send_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.send_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for Sending ICMP Redirects for All Interfaces To set the runtime status of the net.ipv4.conf.all.send_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.all.send_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.all.send_redirects = 0

CM-7 SC-5(1) 1551 Test attestation on 20121024 by DS Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.all.send_redirects # sysctl -q -n -w net.ipv4.conf.all.send_redirects=0 # # If net.ipv4.conf.all.send_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.all.send_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.all.send_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.all.send_redirects.*/net.ipv4.conf.all.send_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.all.send_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.all.send_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.send_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for IP Forwarding To set the runtime status of the net.ipv4.ip_forward kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.ip_forward=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.ip_forward = 0

CM-7 SC-5 366 Test attestation on 20121024 by DS IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers. CCE-RHEL7-CCE-TBD The status of the net.ipv4.ip_forward kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.ip_forward

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. The ability to forward packets is only appropriate for routers. Network Related Kernel Runtime Parameters for Hosts and Routers Certain kernel parameters should be set for systems which are acting as either hosts or routers to improve the system's ability defend against certain types of IPv4 protocol attacks. net.ipv4.conf.all.accept_source_route Trackers could be using source-routed packets to generate traffic that seems to be intra-net, but actually was created outside and has been redirected. 0 1 0 net.ipv4.conf.all.accept_redirects Disable ICMP Redirect Acceptance 0 1 0 net.ipv4.conf.all.secure_redirects Enable to prevent hijacking of routing path by only allowing redirects from gateways known in routing table. 1 1 0 net.ipv4.conf.all.log_martians Disable so you don't Log Spoofed Packets, Source Routed Packets, Redirect Packets 0 1 0 net.ipv4.conf.default.accept_source_route Disable IP source routing? 0 1 0 net.ipv4.conf.default.accept_redirects Disable ICMP Redirect Acceptance? 0 1 0 net.ipv4.conf.default.secure_redirects Log packets with impossible addresses to kernel log? 1 1 0 net.ipv4.icmp_echo_ignore_broadcasts Ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast 1 1 0 net.ipv4.icmp_ignore_bogus_error_responses Enable to prevent unnecessary logging 1 1 0 net.ipv4.tcp_syncookies Enable to turn on TCP SYN Cookie Protection 1 1 0 net.ipv4.conf.all.rp_filter Enable to enforce sanity checking, also called ingress filtering or egress filtering. The point is to drop a packet if the source and destination IP addresses in the IP header do not make sense when considered in light of the physical interface on which it arrived. 1 1 0 net.ipv4.conf.default.rp_filter Enables source route verification 1 1 0 Disable Kernel Parameter for Accepting Source-Routed Packets for All Interfaces To set the runtime status of the net.ipv4.conf.all.accept_source_route kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.all.accept_source_route=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.all.accept_source_route = 0

CM-7 SC-5 1551 Test attestation on 20121024 by DS Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.all.accept_source_route # sysctl -q -n -w net.ipv4.conf.all.accept_source_route=0 # # If net.ipv4.conf.all.accept_source_route present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.all.accept_source_route = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.all.accept_source_route /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.all.accept_source_route to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.all.accept_source_route kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_source_route

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for Accepting ICMP Redirects for All Interfaces To set the runtime status of the net.ipv4.conf.all.accept_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.all.accept_redirects = 0

CM-7 SC-5 1503 1551 Test attestation on 20121024 by DS Accepting ICMP redirects has few legitimate uses. It should be disabled unless it is absolutely required. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.all.accept_redirects # sysctl -q -n -w net.ipv4.conf.all.accept_redirects=0 # # If net.ipv4.conf.all.accept_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.all.accept_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.all.accept_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.all.accept_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.all.accept_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for Accepting Secure Redirects for All Interfaces To set the runtime status of the net.ipv4.conf.all.secure_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.all.secure_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.all.secure_redirects = 0

AC-4 CM-7 SC-5 1503 1551 Test attestation on 20121024 by DS Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.all.secure_redirects # sysctl -q -n -w net.ipv4.conf.all.secure_redirects=0 # # If net.ipv4.conf.all.secure_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.all.secure_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.all.secure_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.all.secure_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.all.secure_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.secure_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Kernel Parameter to Log Martian Packets To set the runtime status of the net.ipv4.conf.all.log_martians kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.all.log_martians=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.all.log_martians = 1

AC-17(7) CM-7 SC-5(3) 126 Test attestation on 20121024 by DS The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.all.log_martians # sysctl -q -n -w net.ipv4.conf.all.log_martians=1 # # If net.ipv4.conf.all.log_martians present in /etc/sysctl.conf, change value to "1" # else, add "net.ipv4.conf.all.log_martians = 1" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.all.log_martians /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.all.log_martians.*/net.ipv4.conf.all.log_martians = 1/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.all.log_martians to 1 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.all.log_martians kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.log_martians

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for Accepting Source-Routed Packets By Default To set the runtime status of the net.ipv4.conf.default.accept_source_route kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.default.accept_source_route = 0

AC-4 CM-7 SC-5 SC-7 1551 Test attestation on 20121024 by DS Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.default.accept_source_route # sysctl -q -n -w net.ipv4.conf.default.accept_source_route=0 # # If net.ipv4.conf.default.accept_source_route present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.default.accept_source_route = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.default.accept_source_route /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.default.accept_source_route.*/net.ipv4.conf.default.accept_source_route = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.default.accept_source_route to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.default.accept_source_route kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.accept_source_route

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for Accepting ICMP Redirects By Default To set the runtime status of the net.ipv4.conf.default.accept_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.default.accept_redirects = 0

AC-4 CM-7 SC-5 SC-7 1551 Test attestation on 20121024 by DS This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.default.accept_redirects # sysctl -q -n -w net.ipv4.conf.default.accept_redirects=0 # # If net.ipv4.conf.default.accept_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.default.accept_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.default.accept_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.default.accept_redirects.*/net.ipv4.conf.default.accept_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.default.accept_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.default.accept_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.accept_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Kernel Parameter for Accepting Secure Redirects By Default To set the runtime status of the net.ipv4.conf.default.secure_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.default.secure_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.default.secure_redirects = 0

AC-4 CM-7 SC-5 SC-7 1551 Test attestation on 20121024 by DS Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.default.secure_redirects # sysctl -q -n -w net.ipv4.conf.default.secure_redirects=0 # # If net.ipv4.conf.default.secure_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv4.conf.default.secure_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.default.secure_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.default.secure_redirects.*/net.ipv4.conf.default.secure_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.default.secure_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.default.secure_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.secure_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Kernel Parameter to Ignore ICMP Broadcast Echo Requests To set the runtime status of the net.ipv4.icmp_echo_ignore_broadcasts kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.icmp_echo_ignore_broadcasts = 1

CM-7 SC-5 1551 Test attestation on 20121024 by DS Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.icmp_echo_ignore_broadcasts # sysctl -q -n -w net.ipv4.icmp_echo_ignore_broadcasts=1 # # If net.ipv4.icmp_echo_ignore_broadcasts present in /etc/sysctl.conf, change value to "1" # else, add "net.ipv4.icmp_echo_ignore_broadcasts = 1" to /etc/sysctl.conf # if grep --silent ^net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf ; then sed -i 's/^net.ipv4.icmp_echo_ignore_broadcasts.*/net.ipv4.icmp_echo_ignore_broadcasts = 1/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.icmp_echo_ignore_broadcasts to 1 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf fi The status of the net.ipv4.icmp_echo_ignore_broadcasts kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_echo_ignore_broadcasts

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Kernel Parameter to Ignore Bogus ICMP Error Responses To set the runtime status of the net.ipv4.icmp_ignore_bogus_error_responses kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.icmp_ignore_bogus_error_responses = 1

CM-7 SC-5 Test attestation on 20121024 by DS Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.icmp_ignore_bogus_error_responses # sysctl -q -n -w net.ipv4.icmp_ignore_bogus_error_responses=1 # # If net.ipv4.icmp_ignore_bogus_error_responses present in /etc/sysctl.conf, change value to "1" # else, add "net.ipv4.icmp_ignore_bogus_error_responses = 1" to /etc/sysctl.conf # if grep --silent ^net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf ; then sed -i 's/^net.ipv4.icmp_ignore_bogus_error_responses.*/net.ipv4.icmp_ignore_bogus_error_responses = 1/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.icmp_ignore_bogus_error_responses to 1 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf fi The status of the net.ipv4.icmp_ignore_bogus_error_responses kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_ignore_bogus_error_responses

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Kernel Parameter to Use TCP Syncookies To set the runtime status of the net.ipv4.tcp_syncookies kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.tcp_syncookies=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.tcp_syncookies = 1

AC-4 SC-5(2) SC-5(3) 1092 1095 Test attestation on 20121024 by DS A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.tcp_syncookies # sysctl -q -n -w net.ipv4.tcp_syncookies=1 # # If net.ipv4.tcp_syncookies present in /etc/sysctl.conf, change value to "1" # else, add "net.ipv4.tcp_syncookies = 1" to /etc/sysctl.conf # if grep --silent ^net.ipv4.tcp_syncookies /etc/sysctl.conf ; then sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.tcp_syncookies to 1 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf fi The status of the net.ipv4.tcp_syncookies kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.tcp_syncookies

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Kernel Parameter to Use Reverse Path Filtering for All Interfaces To set the runtime status of the net.ipv4.conf.all.rp_filter kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.all.rp_filter=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.all.rp_filter = 1

AC-4 SC-5 SC-7 1551 Test attestation on 20121024 by DS Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.all.rp_filter # sysctl -q -n -w net.ipv4.conf.all.rp_filter=1 # # If net.ipv4.conf.all.rp_filter present in /etc/sysctl.conf, change value to "1" # else, add "net.ipv4.conf.all.rp_filter = 1" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.all.rp_filter /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter = 1/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.all.rp_filter to 1 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.all.rp_filter kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.rp_filter

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Enable Kernel Parameter to Use Reverse Path Filtering by Default To set the runtime status of the net.ipv4.conf.default.rp_filter kernel parameter, run the following command:

$ sudo sysctl -w net.ipv4.conf.default.rp_filter=1

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv4.conf.default.rp_filter = 1

AC-4 SC-5 SC-7 Test attestation on 20121024 by DS Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv4.conf.default.rp_filter # sysctl -q -n -w net.ipv4.conf.default.rp_filter=1 # # If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to "1" # else, add "net.ipv4.conf.default.rp_filter = 1" to /etc/sysctl.conf # if grep --silent ^net.ipv4.conf.default.rp_filter /etc/sysctl.conf ; then sed -i 's/^net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter = 1/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv4.conf.default.rp_filter to 1 per security requirements" >> /etc/sysctl.conf echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf fi The status of the net.ipv4.conf.default.rp_filter kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.rp_filter

The output of the command should indicate a value of 1. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Wireless Networking Wireless networking, such as 802.11 (WiFi) and Bluetooth, can present a security risk to sensitive or classified systems and networks. Wireless networking hardware is much more likely to be included in laptop or portable systems than in desktops or servers.

Removal of hardware provides the greatest assurance that the wireless capability remains disabled. Acquisition policies often include provisions to prevent the purchase of equipment that will be used in sensitive spaces and includes wireless capabilities. If it is impractical to remove the wireless hardware, and policy permits the device to enter sensitive spaces as long as wireless is disabled, efforts should instead focus on disabling wireless capability via software. Disable Wireless Through Software Configuration If it is impossible to remove the wireless hardware from the device in question, disable as much of it as possible through software. The following methods can disable software support for wireless networking, but note that these methods do not prevent malicious software or careless users from re-activating the devices. Disable WiFi or Bluetooth in BIOS Some systems that include built-in wireless support offer the ability to disable the device through the BIOS. This is system-specific; consult your hardware manual or explore the BIOS setup during boot. AC-17(8) AC-18(a) AC-18(d) AC-18(3) CM-7 85 Disabling wireless support in the BIOS prevents easy activation of the wireless interface, generally requiring administrators to reboot the system first. CCE-RHEL7-CCE-TBD Deactivate Wireless Network Interfaces Deactivating wireless network interfaces should prevent normal usage of the wireless capability.

First, identify the interfaces available with the command:

$ ifconfig -a

Additionally, the following command may be used to determine whether wireless support is included for a particular interface, though this may not always be a clear indicator:

$ iwconfig

After identifying any wireless interfaces (which may have names like wlan0, ath0, wifi0, em1 or eth0), deactivate the interface with the command:

$ sudo ifdown interface

These changes will only last until the next reboot. To disable the interface for future boots, remove the appropriate interface file from /etc/sysconfig/network-scripts:

$ sudo rm /etc/sysconfig/network-scripts/ifcfg-interface

AC-17(8) AC-18(a) AC-18(d) AC-18(3) CM-7 85 Test attestation on 20121025 by DS Wireless networking allows attackers within physical proximity to launch network-based attacks against systems, including those against local LAN protocols which were not designed with security in mind. CCE-RHEL7-CCE-TBD Disable Bluetooth Service The bluetooth service can be disabled with the following command:

$ sudo systemctl disable bluetooth

$ sudo service bluetooth stop

AC-17(8) AC-18(a) AC-18(d) AC-18(3) CM-7 85 1551 Test attestation on 20121025 by DS Disabling the bluetooth service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range. CCE-RHEL7-CCE-TBD # # Disable bluetooth.service for all systemd targets # systemctl disable bluetooth.service # # Stop bluetooth.service if currently running # systemctl stop bluetooth.service To check that the bluetooth service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled bluetooth

Output should indicate the bluetooth service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled bluetooth
disabled

Run the following command to verify bluetooth is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active bluetooth

If the service is not running the command will return the following output:

inactive

Disable Bluetooth Kernel Modules The kernel's module loading system can be configured to prevent loading of the Bluetooth module. Add the following to the appropriate /etc/modprobe.d configuration file to prevent the loading of the Bluetooth module:

install bluetooth /bin/true

AC-17(8) AC-18(a) AC-18(d) AC-18(3) CM-7 85 1551 Test attestation on 20141031 by JL If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation. CCE-RHEL7-CCE-TBD echo "install bluetooth /bin/true" > /etc/modprobe.d/bluetooth.conf If the system is configured to prevent the loading of the bluetooth kernel module, it will contain lines inside any file in /etc/modprobe.d or the deprecated/etc/modprobe.conf. These lines instruct the module loading system to run another program (such as /bin/true) upon a module install event. Run the following command to search for such lines in all files in /etc/modprobe.d and the deprecated /etc/modprobe.conf:

$ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d

IPv6 The system includes support for Internet Protocol version 6. A major and often-mentioned improvement over IPv4 is its enormous increase in the number of available addresses. Another important feature is its support for automatic configuration of many network settings. Disable Support for IPv6 Unless Needed Despite configuration that suggests support for IPv6 has been disabled, link-local IPv6 address auto-configuration occurs even when only an IPv4 address is assigned. The only way to effectively prevent execution of the IPv6 networking stack is to instruct the system not to activate the IPv6 kernel module. Disable IPv6 Networking Support Automatic Loading To disable support for (ipv6) add the following line to /etc/sysctl.d/ipv6.conf (or another file in /etc/sysctl.d):

net.ipv6.conf.all.disable_ipv6 = 1

This disables IPv6 on all network interfaces as other services and system functionality require the IPv6 stack loaded to work. CM-7 1551 Test attestation on 20121024 by DS Any unnecessary network stacks - including IPv6 - should be disabled, to reduce the vulnerability to exploitation. CCE-RHEL7-CCE-TBD If the system uses IPv6, this is not applicable.

If the system is configured to prevent the usage of the ipv6 on network interfaces, it will contain a line of the form:

net.ipv6.conf.all.disable_ipv6 = 1

Such lines may be inside any file in the /etc/sysctl.d directory. This permits insertion of the IPv6 kernel module (which other parts of the system expect to be present), but otherwise keeps all network interfaces from using IPv6. Run the following command to search for such lines in all files in /etc/sysctl.d:

$ grep -r ipv6 /etc/sysctl.d

Disable Interface Usage of IPv6 To disable interface usage of IPv6, add or correct the following lines in /etc/sysconfig/network:

NETWORKING_IPV6=no
IPV6INIT=no

CCE-RHEL7-CCE-TBD Disable Support for RPC IPv6 RPC services for NFSv4 try to load transport modules for udp6 and tcp6 by default, even if IPv6 has been disabled in /etc/modprobe.d. To prevent RPC services such as rpc.mountd from attempting to start IPv6 network listeners, remove or comment out the following two lines in /etc/netconfig:

udp6       tpi_clts      v     inet6    udp     -       -
tcp6       tpi_cots_ord  v     inet6    tcp     -       -

CM-7 CCE-RHEL7-CCE-TBD Configure IPv6 Settings if Necessary A major feature of IPv6 is the extent to which systems implementing it can automatically configure their networking devices using information from the network. From a security perspective, manually configuring important configuration information is preferable to accepting it from the network in an unauthenticated fashion. Disable Automatic Configuration Disable the system's acceptance of router advertisements and redirects by adding or correcting the following line in /etc/sysconfig/network (note that this does not disable sending router solicitations):

IPV6_AUTOCONF=no

IPV6_AUTOCONF Toggle global IPv6 auto-configuration (only, if global forwarding is disabled) no yes no net.ipv6.conf.default.accept_ra Accept default router advertisements? 0 1 0 net.ipv6.conf.default.accept_redirects Toggle ICMP Redirect Acceptance 0 1 0 Disable Accepting IPv6 Router Advertisements To set the runtime status of the net.ipv6.conf.default.accept_ra kernel parameter, run the following command:

$ sudo sysctl -w net.ipv6.conf.default.accept_ra=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv6.conf.default.accept_ra = 0

CM-7 An illicit router advertisement message could result in a man-in-the-middle attack. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv6.conf.default.accept_ra # sysctl -q -n -w net.ipv6.conf.default.accept_ra=0 # # If net.ipv6.conf.default.accept_ra present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv6.conf.default.accept_ra = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv6.conf.default.accept_ra /etc/sysctl.conf ; then sed -i 's/^net.ipv6.conf.default.accept_ra.*/net.ipv6.conf.default.accept_ra = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv6.conf.default.accept_ra to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf fi The status of the net.ipv6.conf.default.accept_ra kernel parameter can be queried by running the following command:

$ sysctl net.ipv6.conf.default.accept_ra

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Disable Accepting IPv6 Redirects To set the runtime status of the net.ipv6.conf.default.accept_redirects kernel parameter, run the following command:

$ sudo sysctl -w net.ipv6.conf.default.accept_redirects=0

If this is not the system's default value, add the following line to /etc/sysctl.conf:

net.ipv6.conf.default.accept_redirects = 0

CM-7 1551 An illicit ICMP redirect message could result in a man-in-the-middle attack. CCE-RHEL7-CCE-TBD # # Set runtime for net.ipv6.conf.default.accept_redirects # sysctl -q -n -w net.ipv6.conf.default.accept_redirects=0 # # If net.ipv6.conf.default.accept_redirects present in /etc/sysctl.conf, change value to "0" # else, add "net.ipv6.conf.default.accept_redirects = 0" to /etc/sysctl.conf # if grep --silent ^net.ipv6.conf.default.accept_redirects /etc/sysctl.conf ; then sed -i 's/^net.ipv6.conf.default.accept_redirects.*/net.ipv6.conf.default.accept_redirects = 0/g' /etc/sysctl.conf else echo -e "\n# Set net.ipv6.conf.default.accept_redirects to 0 per security requirements" >> /etc/sysctl.conf echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf fi The status of the net.ipv6.conf.default.accept_redirects kernel parameter can be queried by running the following command:

$ sysctl net.ipv6.conf.default.accept_redirects

The output of the command should indicate a value of 0. If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in /etc/sysctl.conf. Manually Assign Global IPv6 Address To manually assign an IP address for an interface, edit the file /etc/sysconfig/network-scripts/ifcfg-interface. Add or correct the following line (substituting the correct IPv6 address):

IPV6ADDR=2001:0DB8::ABCD/64

Manually assigning an IP address is preferable to accepting one from routers or from the network otherwise. The example address here is an IPv6 address reserved for documentation purposes, as defined by RFC3849. CCE-RHEL7-CCE-TBD Use Privacy Extensions for Address To introduce randomness into the automatic generation of IPv6 addresses, add or correct the following line in /etc/sysconfig/network-scripts/ifcfg-interface:

IPV6_PRIVACY=rfc3041

Automatically-generated IPv6 addresses are based on the underlying hardware (e.g. Ethernet) address, and so it becomes possible to track a piece of hardware over its lifetime using its traffic. If it is important for a system's IP address to not trivially reveal its hardware address, this setting should be applied. CCE-RHEL7-CCE-TBD Manually Assign IPv6 Router Address Edit the file /etc/sysconfig/network-scripts/ifcfg-interface, and add or correct the following line (substituting your gateway IP as appropriate):

IPV6_DEFAULTGW=2001:0DB8::0001

Router addresses should be manually set and not accepted via any auto-configuration or router advertisement. CCE-RHEL7-CCE-TBD Limit Network-Transmitted Configuration if Using Static IPv6 Addresses To limit the configuration information requested from other systems and accepted from the network on a system that uses statically-configured IPv6 addresses, add the following lines to /etc/sysctl.conf:

net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1

The router_solicitations setting determines how many router solicitations are sent when bringing up the interface. If addresses are statically assigned, there is no need to send any solicitations.

The accept_ra_pinfo setting controls whether the system will accept prefix info from the router.

The accept_ra_defrtr setting controls whether the system will accept Hop Limit settings from a router advertisement. Setting it to 0 prevents a router from changing your default IPv6 Hop Limit for outgoing packets.

The autoconf setting controls whether router advertisements can cause the system to assign a global unicast address to an interface.

The dad_transmits setting determines how many neighbor solicitations to send out per address (global and link-local) when bringing up an interface to ensure the desired address is unique on the network.

The max_addresses setting determines how many global unicast IPv6 addresses can be assigned to each interface. The default is 16, but it should be set to exactly the number of statically configured global addresses required. firewalld The dynamic firewall daemon firewalld provides a dynamically managed firewall with support for network “zones” to assign a level of trust to a network and its associated connections and interfaces. It has support for IPv4 and IPv6 firewall settings. It supports Ethernet bridges and has a separation of runtime and permanent configuration options. It also has an interface for services or applications to add firewall rules directly.
A graphical configuration tool, firewall-config, is used to configure firewalld, which in turn uses iptables tool to communicate with Netfilter in the kernel which implements packet filtering.
The firewall service provided by firewalld is dynamic rather than static because changes to the configuration can be made at anytime and are immediately implemented. There is no need to save or apply the changes. No unintended disruption of existing network connections occurs as no part of the firewall has to be reloaded. Inspect and Activate Default firewalld Rules Firewalls can be used to separate networks into different zones based on the level of trust the user has decided to place on the devices and traffic within that network. NetworkManager informs firewalld to which zone an interface belongs. An interface's assigned zone can be changed by NetworkManager or via the firewall-config tool.
The zone settings in /etc/firewalld/ are a range of preset settings which can be quickly applied to a network interface. These are the zones provided by firewalld sorted according to the default trust level of the zones from untrusted to trusted:

    drop

    Any incoming network packets are dropped, there is no reply. Only outgoing network connections are possible.
    block

    Any incoming network connections are rejected with an icmp-host-prohibited message for IPv4 and icmp6-adm-prohibited for IPv6. Only network connections initiated from within the system are possible.
    public

    For use in public areas. You do not trust the other computers on the network to not harm your computer. Only selected incoming connections are accepted.
    external

    For use on external networks with masquerading enabled especially for routers. You do not trust the other computers on the network to not harm your computer. Only selected incoming connections are accepted.
    dmz

    For computers in your demilitarized zone that are publicly-accessible with limited access to your internal network. Only selected incoming connections are accepted.
    work

    For use in work areas. You mostly trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.
    home

    For use in home areas. You mostly trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.
    internal

    For use on internal networks. You mostly trust the other computers on the networks to not harm your computer. Only selected incoming connections are accepted.
    trusted

    All network connections are accepted.


It is possible to designate one of these zones to be the default zone. When interface connections are added to NetworkManager, they are assigned to the default zone. On installation, the default zone in firewalld is set to be the public zone.
To find out all the settings of a zone, for example the public zone, enter the following command as root:

# firewall-cmd --zone=public --list-all

Example output of this command might look like the following:


# firewall-cmd --zone=public --list-all
public
  interfaces:
  services: mdns dhcpv6-client ssh
  ports:
  forward-ports:
  icmp-blocks: source-quench

To view the network zones currently active, enter the following command as root:

# firewall-cmd --get-service

The following listing displays the result of this command on common Red Hat Enterprise Linux 7 Server system:


# firewall-cmd --get-service
amanda-client bacula bacula-client dhcp dhcpv6 dhcpv6-client dns ftp high-availability http https imaps ipp ipp-client ipsec kerberos kpasswd ldap ldaps libvirt libvirt-tls mdns mountd ms-wbt mysql nfs ntp openvpn pmcd pmproxy pmwebapi pmwebapis pop3s postgresql proxy-dhcp radius rpc-bind samba samba-client smtp ssh telnet tftp tftp-client transmission-client vnc-server wbem-https

Finally to view the network zones that will be active after the next firewalld service reload, enter the following command as root:

# firewall-cmd --get-service --permanent

Verify firewalld Enabled The firewalld service can be enabled with the following command:

$ sudo systemctl enable firewalld

The dynamic firewall daemon firewalld provides a dynamically managed firewall with support for network “zones”, Ethernet bridges, and has a separation of runtime and permanent configuration options. It has support for both IPv4 and IPv6 firewall settings. CCE-RHEL7-CCE-TBD Run the following command to determine the current status of the firewalld service:

$ systemctl is-active firewalld

If the service is running, it should return the following:

active

iptables and ip6tables A host-based firewall called netfilter is included as part of the Linux kernel distributed with the system. It is activated by default. This firewall is controlled by the program iptables, and the entire capability is frequently referred to by this name. An analogous program called ip6tables handles filtering for IPv6.

Unlike TCP Wrappers, which depends on the network server program to support and respect the rules written, netfilter filtering occurs at the kernel level, before a program can even process the data from the network packet. As such, any program on the system is affected by the rules written.

This section provides basic information about strengthening the iptables and ip6tables configurations included with the system. For more complete information that may allow the construction of a sophisticated ruleset tailored to your environment, please consult the references at the end of this section. Inspect and Activate Default Rules View the currently-enforced iptables rules by running the command:

$ sudo iptables -nL --line-numbers

The command is analogous for ip6tables.

If the firewall does not appear to be active (i.e., no rules appear), activate it and ensure that it starts at boot by issuing the following commands (and analogously for ip6tables):

$ sudo service iptables restart

The default iptables rules are:

Chain INPUT (policy ACCEPT)
num  target     prot opt source       destination
1    ACCEPT     all  --  0.0.0.0/0    0.0.0.0/0    state RELATED,ESTABLISHED 
2    ACCEPT     icmp --  0.0.0.0/0    0.0.0.0/0
3    ACCEPT     all  --  0.0.0.0/0    0.0.0.0/0
4    ACCEPT     tcp  --  0.0.0.0/0    0.0.0.0/0    state NEW tcp dpt:22 
5    REJECT     all  --  0.0.0.0/0    0.0.0.0/0    reject-with icmp-host-prohibited 

Chain FORWARD (policy ACCEPT)
num  target     prot opt source       destination
1    REJECT     all  --  0.0.0.0/0    0.0.0.0/0    reject-with icmp-host-prohibited 

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source       destination

The ip6tables default rules are essentially the same. Verify ip6tables Enabled if Using IPv6 The ip6tables service can be enabled with the following command:

$ sudo systemctl enable ip6tables

AC-4 CA-3(c) CM-7 32 66 1115 1118 1092 1117 1098 1100 1097 1414 Test attestation on 20121024 by DS The ip6tables service provides the system's host-based firewalling capability for IPv6 and ICMPv6. CCE-RHEL7-CCE-TBD # # Enable ip6tables.service for all systemd targets # systemctl enable ip6tables.service # # Start ip6tables.service if not currently running # systemctl start ip6tables.service If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the ip6tables service:

$ systemctl is-active ip6tables

If the service is running, it should return the following:

active

Set Default ip6tables Policy for Incoming Packets To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in /etc/sysconfig/ip6tables:

:INPUT DROP [0:0]

If changes were required, reload the ip6tables rules:

$ sudo service ip6tables reload

CM-7 66 1109 1154 1414 In ip6tables, the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to DROP implements proper design for a firewall, i.e. any packets which are not explicitly permitted should not be accepted. CCE-RHEL7-CCE-TBD If IPv6 is disabled, this is not applicable.

Inspect the file /etc/sysconfig/ip6tables to determine the default policy for the INPUT chain. It should be set to DROP:

$ sudo grep ":INPUT" /etc/sysconfig/ip6tables

Verify iptables Enabled The iptables service can be enabled with the following command:

$ sudo systemctl enable iptables

AC-4 CA-3(c) CM-7 32 66 1115 1118 1092 1117 1098 1100 1097 1414 Test attestation on 20140921 by JL The iptables service provides the system's host-based firewalling capability for IPv4 and ICMP. CCE-RHEL7-CCE-TBD # # Enable iptables.service for all systemd targets # systemctl enable iptables.service # # Start iptables.service if not currently running # systemctl start iptables.service Run the following command to determine the current status of the iptables service:

$ systemctl is-active iptables

If the service is running, it should return the following:

active

Strengthen the Default Ruleset The default rules can be strengthened. The system scripts that activate the firewall rules expect them to be defined in the configuration files iptables and ip6tables in the directory /etc/sysconfig. Many of the lines in these files are similar to the command line arguments that would be provided to the programs /sbin/iptables or /sbin/ip6tables - but some are quite different.

The following recommendations describe how to strengthen the default ruleset configuration file. An alternative to editing this configuration file is to create a shell script that makes calls to the iptables program to load in rules, and then invokes service iptables save to write those loaded rules to /etc/sysconfig/iptables.

The following alterations can be made directly to /etc/sysconfig/iptables and /etc/sysconfig/ip6tables. Instructions apply to both unless otherwise noted. Language and address conventions for regular iptables are used throughout this section; configuration for ip6tables will be either analogous or explicitly covered. The program system-config-securitylevel allows additional services to penetrate the default firewall rules and automatically adjusts /etc/sysconfig/iptables. This program is only useful if the default ruleset meets your security requirements. Otherwise, this program should not be used to make changes to the firewall configuration because it re-writes the saved configuration file. Set Default iptables Policy for Incoming Packets To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in /etc/sysconfig/iptables:

:INPUT DROP [0:0]

CM-7 66 1109 1154 1414 In iptables the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to DROP implements proper design for a firewall, i.e. any packets which are not explicitly permitted should not be accepted. CCE-RHEL7-CCE-TBD Inspect the file /etc/sysconfig/iptables to determine the default policy for the INPUT chain. It should be set to DROP:

$ sudo grep ":INPUT" /etc/sysconfig/iptables

Set Default iptables Policy for Forwarded Packets To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in /etc/sysconfig/iptables:

:FORWARD DROP [0:0]

CM-7 1109 In iptables, the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to DROP implements proper design for a firewall, i.e. any packets which are not explicitly permitted should not be accepted. CCE-RHEL7-CCE-TBD Run the following command to ensure the default FORWARD policy is DROP:

grep ":FORWARD" /etc/sysconfig/iptables

The output should be similar to the following:

$ sudo grep ":FORWARD" /etc/sysconfig/iptables
:FORWARD DROP [0:0

Restrict ICMP Message Types In /etc/sysconfig/iptables, the accepted ICMP messages types can be restricted. To accept only ICMP echo reply, destination unreachable, and time exceeded messages, remove the line:

-A INPUT -p icmp --icmp-type any -j ACCEPT

and insert the lines:

-A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

To allow the system to respond to pings, also insert the following line:

-A INPUT -p icmp --icmp-type echo-request -j ACCEPT

Ping responses can also be limited to certain networks or hosts by using the -s option in the previous rule. Because IPv6 depends so heavily on ICMPv6, it is preferable to deny the ICMPv6 packets you know you don't need (e.g. ping requests) in /etc/sysconfig/ip6tables, while letting everything else through:

-A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP

If you are going to statically configure the machine's address, it should ignore Router Advertisements which could add another IPv6 address to the interface or alter important network settings:

-A INPUT -p icmpv6 --icmpv6-type router-advertisement -j DROP

Restricting ICMPv6 message types in /etc/sysconfig/ip6tables is not recommended because the operation of IPv6 depends heavily on ICMPv6. Thus, great care must be taken if any other ICMPv6 types are blocked. Restricting ICMP messages may make a system slightly less discoverable to an unsophisticated attacker but is not appropriate for many general-purpose use cases and can also make troubleshooting more difficult. Log and Drop Packets with Suspicious Source Addresses Packets with non-routable source addresses should be rejected, as they may indicate spoofing. Because the modified policy will reject non-matching packets, you only need to add these rules if you are interested in also logging these spoofing or suspicious attempts before they are dropped. If you do choose to log various suspicious traffic, add identical rules with a target of DROP after each LOG. To log and then drop these IPv4 packets, insert the following rules in /etc/sysconfig/iptables (excepting any that are intentionally used):

-A INPUT -s 10.0.0.0/8 -j LOG --log-prefix "IP DROP SPOOF A: "
-A INPUT -s 172.16.0.0/12 -j LOG --log-prefix "IP DROP SPOOF B: "
-A INPUT -s 192.168.0.0/16 -j LOG --log-prefix "IP DROP SPOOF C: "
-A INPUT -s 224.0.0.0/4 -j LOG --log-prefix "IP DROP MULTICAST D: "
-A INPUT -s 240.0.0.0/5 -j LOG --log-prefix "IP DROP SPOOF E: "
-A INPUT -d 127.0.0.0/8 -j LOG --log-prefix "IP DROP LOOPBACK: "

Similarly, you might wish to log packets containing some IPv6 reserved addresses if they are not expected on your network:

-A INPUT -i eth0 -s ::1 -j LOG --log-prefix "IPv6 DROP LOOPBACK: "
-A INPUT -s 2002:E000::/20 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "
-A INPUT -s 2002:7F00::/24 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "
-A INPUT -s 2002:0000::/24 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "
-A INPUT -s 2002:FF00::/24 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "
-A INPUT -s 2002:0A00::/24 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "
-A INPUT -s 2002:AC10::/28 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "
-A INPUT -s 2002:C0A8::/32 -j LOG --log-prefix "IPv6 6to4 TRAFFIC: "

If you are not expecting to see site-local multicast or auto-tunneled traffic, you can log those:

-A INPUT -s FF05::/16 -j LOG --log-prefix "IPv6 SITE-LOCAL MULTICAST: "
-A INPUT -s ::0.0.0.0/96 -j LOG --log-prefix "IPv4 COMPATIBLE IPv6 ADDR: "

If you wish to block multicasts to all link-local nodes (e.g. if you are not using router auto-configuration and do not plan to have any services that multicast to the entire local network), you can block the link-local all-nodes multicast address (before accepting incoming ICMPv6):

-A INPUT -d FF02::1 -j LOG --log-prefix "Link-local All-Nodes Multicast: "

However, if you're going to allow IPv4 compatible IPv6 addresses (of the form ::0.0.0.0/96), you should then consider logging the non-routable IPv4-compatible addresses:

-A INPUT -s ::0.0.0.0/104 -j LOG --log-prefix "IP NON-ROUTABLE ADDR: "
-A INPUT -s ::127.0.0.0/104 -j LOG --log-prefix "IP DROP LOOPBACK: "
-A INPUT -s ::224.0.0.0.0/100 -j LOG --log-prefix "IP DROP MULTICAST D: "
-A INPUT -s ::255.0.0.0/104 -j LOG --log-prefix "IP BROADCAST: "

If you are not expecting to see any IPv4 (or IPv4-compatible) traffic on your network, consider logging it before it gets dropped:

-A INPUT -s ::FFFF:0.0.0.0/96 -j LOG --log-prefix "IPv4 MAPPED IPv6 ADDR: "
-A INPUT -s 2002::/16 -j LOG --log-prefix "IPv6 6to4 ADDR: "

The following rule will log all traffic originating from a site-local address, which is deprecated address space:

-A INPUT -s FEC0::/10 -j LOG --log-prefix "SITE-LOCAL ADDRESS TRAFFIC: "

Transport Layer Security Support Support for Transport Layer Security (TLS), and its predecessor, the Secure Sockets Layer (SSL), is included in RHEL in the OpenSSL software (RPM package openssl). TLS provides encrypted and authenticated network communications, and many network services include support for it. TLS or SSL can be leveraged to avoid any plaintext transmission of sensitive data.
For information on how to use OpenSSL, see http://www.openssl.org/docs/HOWTO/. Information on FIPS validation of OpenSSL is available at http://www.openssl.org/docs/fips/fipsvalidation.html and http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm. For information on how to use and implement OpenSSL on Red Hat Enterprise Linux, see https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Using_OpenSSL.html Uncommon Network Protocols The system includes support for several network protocols which are not commonly used. Although security vulnerabilities in kernel networking code are not frequently discovered, the consequences can be dramatic. Ensuring uncommon network protocols are disabled reduces the system's risk to attacks targeted at its implementation of those protocols. Although these protocols are not commonly used, avoid disruption in your network environment by ensuring they are not needed prior to disabling them. Disable DCCP Support The Datagram Congestion Control Protocol (DCCP) is a relatively new transport layer protocol, designed to support streaming media and telephony. To configure the system to prevent the dccp kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install dccp /bin/true

CM-7 Test attestation on 20121024 by DS Disabling DCCP protects the system against exploitation of any flaws in its implementation. CCE-26828-4 echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf If the system is configured to prevent the loading of the dccp kernel module, it will contain lines inside any file in /etc/modprobe.d or the deprecated/etc/modprobe.conf. These lines instruct the module loading system to run another program (such as /bin/true) upon a module install event. Run the following command to search for such lines in all files in /etc/modprobe.d and the deprecated /etc/modprobe.conf:

$ grep -r dccp /etc/modprobe.conf /etc/modprobe.d

Disable SCTP Support The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. To configure the system to prevent the sctp kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install sctp /bin/true

CM-7 Test attestation on 20121024 by DS Disabling SCTP protects the system against exploitation of any flaws in its implementation. CCE-27106-4 echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf If the system is configured to prevent the loading of the sctp kernel module, it will contain lines inside any file in /etc/modprobe.d or the deprecated/etc/modprobe.conf. These lines instruct the module loading system to run another program (such as /bin/true) upon a module install event. Run the following command to search for such lines in all files in /etc/modprobe.d and the deprecated /etc/modprobe.conf:

$ grep -r sctp /etc/modprobe.conf /etc/modprobe.d

Disable RDS Support The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide reliable high- bandwidth, low-latency communications between nodes in a cluster. To configure the system to prevent the rds kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install rds /bin/true

CM-7 382 Test attestation on 20121024 by DS Disabling RDS protects the system against exploitation of any flaws in its implementation. CCE-RHEL7-CCE-TBD echo "install rds /bin/true" > /etc/modprobe.d/rds.conf If the system is configured to prevent the loading of the rds kernel module, it will contain lines inside any file in /etc/modprobe.d or the deprecated/etc/modprobe.conf. These lines instruct the module loading system to run another program (such as /bin/true) upon a module install event. Run the following command to search for such lines in all files in /etc/modprobe.d and the deprecated /etc/modprobe.conf:

$ grep -r rds /etc/modprobe.conf /etc/modprobe.d

Disable TIPC Support The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the tipc kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:

install tipc /bin/true

CM-7 382 Test attestation on 20121024 by DS Disabling TIPC protects the system against exploitation of any flaws in its implementation. CCE-RHEL7-CCE-TBD echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf If the system is configured to prevent the loading of the tipc kernel module, it will contain lines inside any file in /etc/modprobe.d or the deprecated/etc/modprobe.conf. These lines instruct the module loading system to run another program (such as /bin/true) upon a module install event. Run the following command to search for such lines in all files in /etc/modprobe.d and the deprecated /etc/modprobe.conf:

$ grep -r tipc /etc/modprobe.conf /etc/modprobe.d

IPSec Support Support for Internet Protocol Security (IPsec) is provided in RHEL 7 with Libreswan. Install libreswan Package The Libreswan package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The libreswan package can be installed with the following command:

$ sudo yum install libreswan

AC-17 MA-4 SC-9 1130 1131 Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network. CCE-RHEL7-CCE-TBD yum -y install libreswan Run the following command to determine if the libreswan package is installed:

$ rpm -q libreswan

Configure Syslog The syslog service has been the default Unix logging mechanism for many years. It has a number of downsides, including inconsistent log format, lack of authentication for received messages, and lack of authentication, encryption, or reliable transport for messages sent over a network. However, due to its long history, syslog is a de facto standard which is supported by almost all Unix applications.

In RHEL 7, rsyslog has replaced ksyslogd as the syslog daemon of choice, and it includes some additional security features such as reliable, connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server. This section discusses how to configure rsyslog for best effect, and how to use tools provided with the system to maintain and monitor logs. Ensure rsyslog is Installed Rsyslog is installed by default. The rsyslog package can be installed with the following command:

$ sudo yum install rsyslog

AU-9(2) 1311 1312 Test attestation on 20121024 by DS The rsyslog package provides the rsyslog daemon, which provides system logging services. CCE-RHEL7-CCE-TBD yum -y install rsyslog Run the following command to determine if the rsyslog package is installed:

$ rpm -q rsyslog

Enable rsyslog Service The rsyslog service provides syslog-style logging by default on RHEL 7. The rsyslog service can be enabled with the following command:

$ sudo systemctl enable rsyslog

AU-12 1557 1312 1311 Test attestation on 20121024 by DS The rsyslog service must be running in order to provide logging services, which are essential to system administration. CCE-RHEL7-CCE-TBD # # Enable rsyslog.service for all systemd targets # systemctl enable rsyslog.service # # Start rsyslog.service if not currently running # systemctl start rsyslog.service Run the following command to determine the current status of the rsyslog service:

$ systemctl is-active rsyslog

If the service is running, it should return the following:

active

Ensure Proper Configuration of Log Files The file /etc/rsyslog.conf controls where log message are written. These are controlled by lines called rules, which consist of a selector and an action. These rules are often customized depending on the role of the system, the requirements of the environment, and whatever may enable the administrator to most effectively make use of log data. The default rules in RHEL 7 are:

*.info;mail.none;authpriv.none;cron.none                /var/log/messages
authpriv.*                                              /var/log/secure
mail.*                                                  -/var/log/maillog
cron.*                                                  /var/log/cron
*.emerg                                                 *
uucp,news.crit                                          /var/log/spooler
local7.*                                                /var/log/boot.log

See the man page rsyslog.conf(5) for more information. Note that the rsyslog daemon can be configured to use a timestamp format that some log processing programs may not understand. If this occurs, edit the file /etc/rsyslog.conf and add or edit the following line:

$ ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

User who owns log files Specify user owner of all logfiles specified in /etc/rsyslog.conf. root group who owns log files Specify group owner of all logfiles specified in /etc/rsyslog.conf. root Ensure Log Files Are Owned By Appropriate User The owner of all log files written by rsyslog should be root. These log files are determined by the second part of each Rule line in /etc/rsyslog.conf and typically all appear in /var/log. For each log file LOGFILE referenced in /etc/rsyslog.conf, run the following command to inspect the file's owner:

$ ls -l LOGFILE

If the owner is not root, run the following command to correct this:

$ sudo chown root LOGFILE

AC-6 1314 Test attestation on 20121024 by DS The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access. CCE-RHEL7-CCE-TBD The owner of all log files written by rsyslog should be root. These log files are determined by the second part of each Rule line in /etc/rsyslog.conf and typically all appear in /var/log. To see the owner of a given log file, run the following command:

$ ls -l LOGFILE

Ensure Log Files Are Owned By Appropriate Group The group-owner of all log files written by rsyslog should be root. These log files are determined by the second part of each Rule line in /etc/rsyslog.conf and typically all appear in /var/log. For each log file LOGFILE referenced in /etc/rsyslog.conf, run the following command to inspect the file's group owner:

$ ls -l LOGFILE

If the owner is not root, run the following command to correct this:

$ sudo chgrp root LOGFILE

AC-6 1314 Test attestation on 20121024 by DS The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access. CCE-RHEL7-CCE-TBD The group-owner of all log files written by rsyslog should be root. These log files are determined by the second part of each Rule line in /etc/rsyslog.conf and typically all appear in /var/log. To see the group-owner of a given log file, run the following command:

$ ls -l LOGFILE

Ensure System Log Files Have Correct Permissions The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in /etc/rsyslog.conf and typically all appear in /var/log. For each log file LOGFILE referenced in /etc/rsyslog.conf, run the following command to inspect the file's permissions:

$ ls -l LOGFILE

If the permissions are not 600 or more restrictive, run the following command to correct this:

$ sudo chmod 0600 LOGFILE

1314 Test attestation on 20121024 by DS Log files can contain valuable information regarding system configuration. If the system log files are not protected unauthorized users could change the logged data, eliminating their forensic value. CCE-RHEL7-CCE-TBD The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in /etc/rsyslog.conf and typically all appear in /var/log. To see the permissions of a given log file, run the following command:

$ ls -l LOGFILE

The permissions should be 600, or more restrictive. Rsyslog Logs Sent To Remote Host If system logs are to be useful in detecting malicious activities, it is necessary to send logs to a remote server. An intruder who has compromised the root account on a machine may delete the log entries which indicate that the system was attacked before they are seen by an administrator.

However, it is recommended that logs be stored on the local host in addition to being sent to the loghost, especially if rsyslog has been configured to use the UDP protocol to send messages over a network. UDP does not guarantee reliable delivery, and moderately busy sites will lose log messages occasionally, especially in periods of high traffic which may be the result of an attack. In addition, remote rsyslog messages are not authenticated in any way by default, so it is easy for an attacker to introduce spurious messages to the central log server. Also, some problems cause loss of network connectivity, which will prevent the sending of messages to the central server. For all of these reasons, it is better to store log messages both centrally and on each host, so that they can be correlated if necessary. Ensure Logs Sent To Remote Host To configure rsyslog to send logs to a remote log server, open /etc/rsyslog.conf and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting loghost.example.com appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments.
To use UDP for log message delivery:

*.* @loghost.example.com


To use TCP for log message delivery:

*.* @@loghost.example.com


To use RELP for log message delivery:

*.* :omrelp:loghost.example.com

AU-3(2) AU-9 1348 136 A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise. CCE-RHEL7-CCE-TBD To ensure logs are sent to a remote host, examine the file /etc/rsyslog.conf. If using UDP, a line similar to the following should be present:

 *.* @loghost.example.com

If using TCP, a line similar to the following should be present:

 *.* @@loghost.example.com

If using RELP, a line similar to the following should be present:

 *.* :omrelp:loghost.example.com

Configure rsyslogd to Accept Remote Messages If Acting as a Log Server By default, rsyslog does not listen over the network for log messages. If needed, modules can be enabled to allow the rsyslog daemon to receive messages from other systems and for the system thus to act as a log server. If the machine is not a log server, then lines concerning these modules should remain commented out.

Ensure rsyslog Does Not Accept Remote Messages Unless Acting As Log Server The rsyslog daemon should not accept remote messages unless the system acts as a log server. To ensure that it is not listening on the network, ensure the following lines are not found in /etc/rsyslog.conf:

$ModLoad imtcp
$InputTCPServerRun port
$ModLoad imudp
$UDPServerRun port
$ModLoad imrelp
$InputRELPServerRun port

AU-9(2) AC-4 Any process which receives messages from the network incurs some risk of receiving malicious messages. This risk can be eliminated for rsyslog by configuring it not to listen on the network. CCE-RHEL7-CCE-TBD Enable rsyslog to Accept Messages via TCP, if Acting As Log Server The rsyslog daemon should not accept remote messages unless the system acts as a log server. If the system needs to act as a central log server, add the following lines to /etc/rsyslog.conf to enable reception of messages over TCP:

$ModLoad imtcp
$InputTCPServerRun 514

AU-9 If the system needs to act as a log server, this ensures that it can receive messages over a reliable TCP connection. CCE-RHEL7-CCE-TBD Enable rsyslog to Accept Messages via UDP, if Acting As Log Server The rsyslog daemon should not accept remote messages unless the system acts as a log server. If the system needs to act as a central log server, add the following lines to /etc/rsyslog.conf to enable reception of messages over UDP:

$ModLoad imudp
$UDPServerRun 514

AU-9 Many devices, such as switches, routers, and other Unix-like systems, may only support the traditional syslog transmission over UDP. If the system must act as a log server, this enables it to receive their messages as well. CCE-RHEL7-CCE-TBD Ensure All Logs are Rotated by logrotate Edit the file /etc/logrotate.d/syslog. Find the first line, which should look like this (wrapped for clarity):

/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler \
  /var/log/boot.log /var/log/cron {

Edit this line so that it contains a one-space-separated listing of each log file referenced in /etc/rsyslog.conf.

All logs in use on a system must be rotated regularly, or the log files will consume disk space over time, eventually interfering with system operation. The file /etc/logrotate.d/syslog is the configuration file used by the logrotate program to maintain all log files written by syslog. By default, it rotates logs weekly and stores four archival copies of each log. These settings can be modified by editing /etc/logrotate.conf, but the defaults are sufficient for purposes of this guide.

Note that logrotate is run nightly by the cron job /etc/cron.daily/logrotate. If particularly active logs need to be rotated more often than once a day, some other mechanism must be used. Ensure Logrotate Runs Periodically The logrotate utility allows for the automatic rotation of log files. The frequency of rotation is specified in /etc/logrotate.conf, which triggers a cron task. To configure logrotate to run daily, add or correct the following line in /etc/logrotate.conf:

# rotate log files frequency
daily

AU-9 366 Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full. CCE-RHEL7-CCE-TBD To determine the status and frequency of logrotate, run the following command:

$ sudo grep logrotate /var/log/cron*

If logrotate is configured properly, output should include references to /etc/cron.daily. Configure Logwatch on the Central Log Server Is this machine the central log server? If so, edit the file /etc/logwatch/conf/logwatch.conf as shown below. Configure Logwatch HostLimit Line On a central logserver, you want Logwatch to summarize all syslog entries, including those which did not originate on the logserver itself. The HostLimit setting tells Logwatch to report on all hosts, not just the one on which it is running.

 HostLimit = no 

CCE-RHEL7-CCE-TBD Configure Logwatch SplitHosts Line If SplitHosts is set, Logwatch will separate entries by hostname. This makes the report longer but significantly more usable. If it is not set, then Logwatch will not report which host generated a given log entry, and that information is almost always necessary

 SplitHosts = yes 

CCE-RHEL7-CCE-TBD Disable Logwatch on Clients if a Logserver Exists Does your site have a central logserver which has been configured to report on logs received from all systems? If so:

 
$ sudo rm /etc/cron.daily/0logwatch 

If no logserver exists, it will be necessary for each machine to run Logwatch individually. Using a central logserver provides the security and reliability benefits discussed earlier, and also makes monitoring logs easier and less time-intensive for administrators. CCE-RHEL7-CCE-TBD System Accounting with auditd The audit service provides substantial capabilities for recording system activities. By default, the service audits about SELinux AVC denials and certain types of security-relevant events such as system logins, account modifications, and authentication events performed by programs such as sudo. Under its default configuration, auditd has modest disk space requirements, and should not noticeably impact system performance.
NOTE: The Linux Audit daemon auditd can be configured to use the augenrules program to read audit rules files (*.rules) located in /etc/audit/rules.d location and compile them to create the resulting form of the /etc/audit/audit.rules configuration file during the daemon startup (default configuration). Alternatively, the auditd daemon can use the auditctl utility to read audit rules from the /etc/audit/audit.rules configuration file during daemon startup, and load them into the kernel. The expected behavior is configured via the appropriate ExecStartPost directive setting in the /usr/lib/systemd/system/auditd.service configuration file. To instruct the auditd daemon to use the augenrules program to read audit rules (default configuration), use the following setting:

ExecStartPost=-/sbin/augenrules --load

in the /usr/lib/systemd/system/auditd.service configuration file. In order to instruct the auditd daemon to use the auditctl utility to read audit rules, use the following setting:

ExecStartPost=-/sbin/auditctl -R /etc/audit/audit.rules

in the /usr/lib/systemd/system/auditd.service configuration file. Refer to [Service] section of the /usr/lib/systemd/system/auditd.service configuration file for further details.
Government networks often have substantial auditing requirements and auditd can be configured to meet these requirements. Examining some example audit records demonstrates how the Linux audit system satisfies common requirements. The following example from Fedora Documentation available at https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Fixing_Problems.html#sect-Security-Enhanced_Linux-Fixing_Problems-Raw_Audit_Messages shows the substantial amount of information captured in a two typical "raw" audit messages, followed by a breakdown of the most important fields. In this example the message is SELinux-related and reports an AVC denial (and the associated system call) that occurred when the Apache HTTP Server attempted to access the /var/www/html/file1 file (labeled with the samba_share_t type):

type=AVC msg=audit(1226874073.147:96): avc:  denied  { getattr } for pid=2465 comm="httpd"
path="/var/www/html/file1" dev=dm-0 ino=284133 scontext=unconfined_u:system_r:httpd_t:s0
tcontext=unconfined_u:object_r:samba_share_t:s0 tclass=file

type=SYSCALL msg=audit(1226874073.147:96): arch=40000003 syscall=196 success=no exit=-13
a0=b98df198 a1=bfec85dc a2=54dff4 a3=2008171 items=0 ppid=2463 pid=2465 auid=502 uid=48
gid=48 euid=48 suid=48 fsuid=48 egid=48 sgid=48 fsgid=48 tty=(none) ses=6 comm="httpd"
exe="/usr/sbin/httpd" subj=unconfined_u:system_r:httpd_t:s0 key=(null)

    msg=audit(1226874073.147:96)
        The number in parentheses is the unformatted time stamp (Epoch time) for the event, which can be converted to standard time by using the date command. 
    { getattr }
        The item in braces indicates the permission that was denied. getattr indicates the source process was trying to read the target file's status information. This occurs before reading files. This action is denied due to the file being accessed having the wrong label. Commonly seen permissions include getattr, read, and write.
    comm="httpd"
        The executable that launched the process. The full path of the executable is found in the exe= section of the system call (SYSCALL) message, which in this case, is exe="/usr/sbin/httpd". 
    path="/var/www/html/file1"
        The path to the object (target) the process attempted to access. 
    scontext="unconfined_u:system_r:httpd_t:s0"
        The SELinux context of the process that attempted the denied action. In this case, it is the SELinux context of the Apache HTTP Server, which is running in the httpd_t domain. 
    tcontext="unconfined_u:object_r:samba_share_t:s0"
        The SELinux context of the object (target) the process attempted to access. In this case, it is the SELinux context of file1. Note: the samba_share_t type is not accessible to processes running in the httpd_t domain.
    From the system call (SYSCALL) message, two items are of interest:
        success=no: indicates whether the denial (AVC) was enforced or not. success=no indicates the system call was not successful (SELinux denied access). success=yes indicates the system call was successful - this can be seen for permissive domains or unconfined domains, such as initrc_t and kernel_t.
        exe="/usr/sbin/httpd": the full path to the executable that launched the process, which in this case, is exe="/usr/sbin/httpd". 

Enable auditd Service The auditd service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The auditd service can be enabled with the following command:

$ sudo systemctl enable auditd

AC-17(1) AU-1(b) AU-10 AU-12(a) AU-12(c) IR-5 347 157 172 880 1353 1462 1487 1115 1454 067 158 831 1190 1312 1263 130 120 1589 Test attestation on 20121024 by DS Ensuring the auditd service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist. CCE-RHEL7-CCE-TBD # # Enable auditd.service for all systemd targets # systemctl enable auditd.service # # Start auditd.service if not currently running # systemctl start auditd.service Run the following command to determine the current status of the auditd service:

$ systemctl is-active auditd

If the service is running, it should return the following:

active

Enable Auditing for Processes Which Start Prior to the Audit Daemon To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument audit=1 to the kernel line in /etc/grub.conf, in the manner below:

kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1

AC-17(1) AU-14(1) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-10 IR-5 1464 130 Each process on the system carries an "auditable" flag which indicates whether its activities can be audited. Although auditd takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot. CCE-RHEL7-CCE-TBD Inspect the kernel boot arguments (which follow the word kernel) in /etc/grub.conf. If they include audit=1, then auditing is enabled at boot time. Configure auditd Data Retention The audit system writes data to /var/log/audit/audit.log. By default, auditd rotates 5 logs by size (6MB), retaining a maximum of 30MB of data in total, and refuses to write entries when the disk is too full. This minimizes the risk of audit data filling its partition and impacting other services. This also minimizes the risk of the audit daemon temporarily disabling the system if it cannot write audit log (which it can be configured to do). For a busy system or a system which is thoroughly auditing system activity, the default settings for data retention may be insufficient. The log file size needed will depend heavily on what types of events are being audited. First configure auditing to log all the events of interest. Then monitor the log size manually for awhile to determine what file size will allow you to keep the required data for the correct time period.

Using a dedicated partition for /var/log/audit prevents the auditd logs from disrupting system functionality if they fill, and, more importantly, prevents other activity in /var from filling the partition and stopping the audit trail. (The audit logs are size-limited and therefore unlikely to grow without bound unless configured to do so.) Some machines may have requirements that no actions occur which cannot be audited. If this is the case, then auditd can be configured to halt the machine if it runs out of space. Note: Since older logs are rotated, configuring auditd this way does not prevent older logs from being rotated away before they can be viewed. If your system is configured to halt when logging cannot be performed, make sure this can never happen under normal circumstances! Ensure that /var/log/audit is on its own partition, and that this partition is larger than the maximum amount of data auditd will retain normally. AU-11 138 Number of log files for auditd to retain The setting for num_logs in /etc/audit/auditd.conf 5 5 4 3 2 1 0 Maximum audit log file size for auditd The setting for max_log_size in /etc/audit/auditd.conf 6 20 10 6 5 1 Action for auditd to take when log files reach their maximum size The setting for max_log_file_action in /etc/audit/auditd.conf rotate ignore syslog suspend rotate keep_logs Action for auditd to take when disk space just starts to run low The setting for space_left_action in /etc/audit/auditd.conf email ignore syslog email exec suspend single halt Action for auditd to take when disk space just starts to run low The setting for space_left_action in /etc/audit/auditd.conf single ignore syslog email exec suspend single halt Account for auditd to send email when actions occurs The setting for action_mail_acct in /etc/audit/auditd.conf root root admin Configure auditd Number of Logs Retained Determine how many log files auditd should retain when it rotates logs. Edit the file /etc/audit/auditd.conf. Add or modify the following line, substituting NUMLOGS with the correct value:

num_logs = NUMLOGS

Set the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation. AU-1(b) AU-11 IR-5 Test attestation on 20121024 by DS The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained. CCE-RHEL7-CCE-TBD Inspect /etc/audit/auditd.conf and locate the following line to determine how many logs the system is configured to retain after rotation: $ sudo grep num_logs /etc/audit/auditd.conf

num_logs = 5

Configure auditd Max Log File Size Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file /etc/audit/auditd.conf. Add or modify the following line, substituting the correct value for STOREMB:

max_log_file = STOREMB

Set the value to 6 (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data. AU-1(b) AU-11 IR-5 Test attestation on 20121024 by DS The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained. CCE-RHEL7-CCE-TBD Inspect /etc/audit/auditd.conf and locate the following line to determine how much data the system will retain in each audit log file: $ sudo grep max_log_file /etc/audit/auditd.conf

max_log_file = 6

Configure auditd max_log_file_action Upon Reaching Maximum Log Size The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one. To configure the action taken by auditd, add or correct the line in /etc/audit/auditd.conf:

max_log_file_action = ACTION

Possible values for ACTION are described in the auditd.conf man page. These include:

    ignore
    syslog
    suspend
    rotate
    keep_logs

Set the ACTION to rotate to ensure log rotation occurs. This is the default. The setting is case-insensitive. AU-1(b) AU-4 AU-11 IR-5 Test attestation on 20121024 by DS Automatically rotating logs (by setting this to rotate) minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, keep_logs can be employed. CCE-RHEL7-CCE-TBD Inspect /etc/audit/auditd.conf and locate the following line to determine if the system is configured to rotate logs when they reach their maximum size: $ sudo grep max_log_file_action /etc/audit/auditd.conf

max_log_file_action rotate

Configure auditd space_left Action on Low Disk Space The auditd service can be configured to take an action when disk space starts to run low. Edit the file /etc/audit/auditd.conf. Modify the following line, substituting ACTION appropriately:

space_left_action = ACTION

Possible values for ACTION are described in the auditd.conf man page. These include:

    ignore
    syslog
    email
    exec
    suspend
    single
    halt

Set this to email (instead of the default, which is suspend) as it is more likely to get prompt attention. Acceptable values also include suspend, single, and halt. AU-1(b) AU-4 AU-5(b) IR-5 140 143 Test attestation on 20121024 by DS Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption. CCE-RHEL7-CCE-TBD Inspect /etc/audit/auditd.conf and locate the following line to determine if the system is configured to email the administrator when disk space is starting to run low: $ sudo grep space_left_action /etc/audit/auditd.conf

space_left_action

Acceptable values are email, suspend, single, and halt. Configure auditd admin_space_left Action on Low Disk Space The auditd service can be configured to take an action when disk space is running low but prior to running out of space completely. Edit the file /etc/audit/auditd.conf. Add or modify the following line, substituting ACTION appropriately:

admin_space_left_action = ACTION

Set this value to single to cause the system to switch to single user mode for corrective action. Acceptable values also include suspend and halt. For certain systems, the need for availability outweighs the need to log all actions, and a different setting should be determined. Details regarding all possible values for ACTION are described in the auditd.conf man page. AU-1(b) AU-4 AU-5(b) IR-5 140 1343 Test attestation on 20121024 by DS Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur. CCE-RHEL7-CCE-TBD var_auditd_admin_space_left_action="" grep -q ^admin_space_left_action /etc/audit/auditd.conf && \ sed -i "s/admin_space_left_action.*/admin_space_left_action = $var_auditd_admin_space_left_action/g" /etc/audit/auditd.conf if ! [ $? -eq 0 ]; then echo "admin_space_left_action = $var_auditd_admin_space_left_action" >> /etc/audit/auditd.conf fi Inspect /etc/audit/auditd.conf and locate the following line to determine if the system is configured to either suspend, switch to single user mode, or halt when disk space has run low:

admin_space_left_action single

Configure auditd mail_acct Action on Low Disk Space The auditd service can be configured to send email to a designated account in certain situations. Add or correct the following line in /etc/audit/auditd.conf to ensure that administrators are notified via email for those situations:

action_mail_acct = root

AU-1(b) AU-4 AU-5(a) IR-5 139 144 Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action. CCE-RHEL7-CCE-TBD Inspect /etc/audit/auditd.conf and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator:

action_mail_acct = root

Configure auditd to use audispd plugin To configure the auditd service to use the audispd plugin, set the active line in /etc/audisp/plugins.d/syslog.conf to yes. Restart the auditdservice:

$ sudo service auditd restart

AU-1(b) AU-3(2) IR-5 136 The auditd service does not include the ability to send audit records to a centralized server for management directly. It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server CCE-RHEL7-CCE-TBD To verify the audispd plugin is active, run the following command:

$ sudo grep active /etc/audisp/plugins.d/syslog.conf

If the plugin is active, the output will show yes. Configure auditd Rules for Comprehensive Auditing The auditd program can perform comprehensive monitoring of system activity. This section describes recommended configuration settings for comprehensive auditing, but a full description of the auditing system's capabilities is beyond the scope of this guide. The mailing list linux-audit@redhat.com exists to facilitate community discussion of the auditing system.

The audit subsystem supports extensive collection of events, including:

    Tracing of arbitrary system calls (identified by name or number) on entry or exit.
    Filtering by PID, UID, call success, system call argument (with some limitations), etc.
    Monitoring of specific files for modifications to the file's contents or metadata.


Auditing rules at startup are controlled by the file /etc/audit/audit.rules. Add rules to it to meet the auditing requirements for your organization. Each line in /etc/audit/audit.rules represents a series of arguments that can be passed to auditctl and can be individually tested during runtime. See documentation in /usr/share/doc/audit-VERSION and in the related man pages for more details.

If copying any example audit rulesets from /usr/share/doc/audit-VERSION, be sure to comment out the lines containing arch= which are not appropriate for your system's architecture. Then review and understand the following rules, ensuring rules are activated as needed for the appropriate architecture.

After reviewing all the rules, reading the following sections, and editing as needed, the new rules can be activated as follows:

$ sudo service auditd restart

Records Events that Modify Date and Time Information Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time. All changes to the system time should be audited. Record attempts to alter time through adjtimex If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls:

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 1487 169 Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the adjtimex system call, run the following command:

$ sudo grep "adjtimex" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record attempts to alter time through settimeofday If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls:

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 1487 169 Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the settimeofday system call, run the following command:

$ sudo grep "settimeofday" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Attempts to Alter Time Through stime If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d for both 32 bit and 64 bit systems:

-a always,exit -F arch=b32 -S stime -k audit_time_rules

Since the 64 bit version of the "stime" system call is not defined in the audit lookup table, the corresponding "-F arch=b64" form of this rule is not expected to be defined on 64 bit systems (the aforementioned "-F arch=b32" stime rule form itself is sufficient for both 32 bit and 64 bit systems). If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file for both 32 bit and 64 bit systems:

-a always,exit -F arch=b32 -S stime -k audit_time_rules

Since the 64 bit version of the "stime" system call is not defined in the audit lookup table, the corresponding "-F arch=b64" form of this rule is not expected to be defined on 64 bit systems (the aforementioned "-F arch=b32" stime rule form itself is sufficient for both 32 bit and 64 bit systems). The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined system calls:

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 1487 169 Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited. CCE-RHEL7-CCE-TBD If the system is not configured to audit time changes, this is a finding. If the system is 64-bit only, this is not applicable
To determine if the system is configured to audit calls to the stime system call, run the following command:

$ sudo grep "stime" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Attempts to Alter Time Through clock_settime If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls:

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 1487 169 Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the clock_settime system call, run the following command:

$ sudo grep "clock_settime" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Attempts to Alter the localtime File If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-w /etc/localtime -p wa -k audit_time_rules

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-w /etc/localtime -p wa -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(b) IR-5 1487 169 Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit attempts to alter time via the /etc/localtime file, run the following command:

$ sudo auditctl -l | grep "watch=/etc/localtime"

If the system is configured to audit this activity, it will return a line. Record Events that Modify User/Group Information If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, in order to capture events that modify account changes:

-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, in order to capture events that modify account changes:

-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

AC-2(4) AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 18 172 1403 1404 1405 1684 1683 1685 1686 476 239 In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy. CCE-27192-4 To determine if the system is configured to audit account changes, run the following command:

auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)'

If the system is configured to watch for account changes, lines should be returned for each file specified (and with perm=wa for each). Record Events that Modify the System's Network Environment If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit changes to its network configuration, run the following command:

auditctl -l | egrep '(/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)'

If the system is configured to watch for network configuration changes, a line should be returned for each file specified (and perm=wa should be indicated for each). System Audit Logs Must Have Mode 0640 or Less Permissive Change the mode of the audit log files with the following command:

$ sudo chmod 0640 audit_file

AC-6 AU-1(b) AU-9 IR-5 Test attestation on 20121024 by DS If users can write to audit logs, audit trails can be modified or destroyed. CCE-27004-1 chmod -R 640 /var/log/audit/* chmod 640 /etc/audit/audit.rules Run the following command to check the mode of the system audit logs:

$ sudo ls -l /var/log/audit

Audit logs must be mode 0640 or less permissive. System Audit Logs Must Be Owned By Root To properly set the owner of /var/log, run the command:

$ sudo chown root /var/log

AC-6 AU-1(b) AU-9 IR-5 166 Test attestation on 20121024 by DS Failure to give ownership of the audit log files to root allows the designated owner, and unauthorized users, potential access to sensitive information. CCE-RHEL7-CCE-TBD To check the ownership of /var/log, run the command:

$ ls -lL /var/log

If properly configured, the output should indicate the following owner: root Record Events that Modify the System's Mandatory Access Controls If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-w /etc/selinux/ -p wa -k MAC-policy

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-w /etc/selinux/ -p wa -k MAC-policy

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 The system's mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit changes to its SELinux configuration files, run the following command:

$ sudo auditctl -l | grep "dir=/etc/selinux"

If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including perm=wa indicating permissions that are watched). Record Events that Modify the System's Discretionary Access Controls At a minimum the audit system should collect file permission changes for all users and root. Note that the "-F arch=b32" lines should be present even on a 64 bit system. These commands identify system calls for auditing. Even if the system is 64 bit it can still execute 32 bit system calls. Additionally, these rules can be configured in a number of ways while still achieving the desired effect. An example of this is that the "-S" calls could be split up and placed on separate lines, however, this is less efficient. Add the following to /etc/audit/audit.rules:

-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If your system is 64 bit then these lines should be duplicated and the arch=b32 replaced with arch=b64 as follows:

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. Record Events that Modify the System's Discretionary Access Controls - chmod At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S chmod  -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S chmod  -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the chmod system call, run the following command:

$ sudo grep "chmod" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - chown At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the chown system call, run the following command:

$ sudo grep "chown" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - fchmod At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the fchmod system call, run the following command:

$ sudo grep "fchmod" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - fchmodat At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the fchmodat system call, run the following command:

$ sudo grep "fchmodat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - fchown At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the fchown system call, run the following command:

$ sudo grep "fchown" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - fchownat At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the fchownat system call, run the following command:

$ sudo grep "fchownat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - fremovexattr At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the fremovexattr system call, run the following command:

$ sudo grep "fremovexattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - fsetxattr At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the fsetxattr system call, run the following command:

$ sudo grep "fsetxattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - lchown At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the lchown system call, run the following command:

$ sudo grep "lchown" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - lremovexattr At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the lremovexattr system call, run the following command:

$ sudo grep "lremovexattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - lsetxattr At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the lsetxattr system call, run the following command:

$ sudo grep "lsetxattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - removexattr At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the removexattr system call, run the following command:

$ sudo grep "removexattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Events that Modify the System's Discretionary Access Controls - setxattr At a minimum the audit system should collect file permission changes for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the system is 64 bit then also add the following line:

-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

Note that these rules can be configured in a number of ways while still achieving the desired effect. Here the system calls have been placed independent of other system calls. Grouping these system calls with others as identifying earlier in this guide is more efficient. AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users. CCE-RHEL7-CCE-TBD To determine if the system is configured to audit calls to the setxattr system call, run the following command:

$ sudo grep "setxattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Record Attempts to Alter Logon and Logout Events The audit system already collects login information for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d in order to watch for attempted manual edits of files involved in storing logon events:

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file in order to watch for unattempted manual edits of files involved in storing logon events:

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

AC-17(7) AU-1(b) AU-12(a) AU-12(c) IR-5 Manual editing of these files may indicate nefarious activity, such as an attacker attempting to remove evidence of an intrusion. CCE-27204-7 Record Attempts to Alter Process and Session Initiation Information The audit system already collects process information for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d in order to watch for attempted manual edits of files involved in storing such process information:

-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file in order to watch for attempted manual edits of files involved in storing such process information:

-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 Manual editing of these files may indicate nefarious activity, such as an attacker attempting to remove evidence of an intrusion. CCE-27301-1 Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful) At a minimum the audit system should collect unauthorized file accesses for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d:

-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

If the system is 64 bit then also add the following lines:


-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file:

-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

If the system is 64 bit then also add the following lines:


-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise. CCE-RHEL7-CCE-TBD To verify that the audit system collects unauthorized file accesses, run the following commands:

$ sudo grep EACCES /etc/audit/audit.rules

$ sudo grep EPERM /etc/audit/audit.rules

Ensure auditd Collects Information on the Use of Privileged Commands At a minimum the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid / setgid programs, run the following command for each local partition PART:

$ sudo find PART -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null

If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add a line of the following form to a file with suffix .rules in the directory /etc/audit/rules.d for each setuid / setgid program on the system, replacing the SETUID_PROG_PATH part with the full path of that setuid / setgid program in the list:

-a always,exit -F path=SETUID_PROG_PATH -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add a line of the following form to /etc/audit/audit.rules for each setuid / setgid program on the system, replacing the SETUID_PROG_PATH part with the full path of that setuid / setgid program in the list:

-a always,exit -F path=SETUID_PROG_PATH -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-2(4) AU-12(a) AU-12(c) IR-5 40 Test attestation on 20121024 by DS Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity. CCE-RHEL7-CCE-TBD To verify that auditing of privileged command use is configured, run the following command for each local partition PART to find relevant setuid / setgid programs:

$ sudo find PART -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command:

$ sudo grep path /etc/audit/audit.rules

It should be the case that all relevant setuid / setgid programs have a line in the audit rules. Ensure auditd Collects Information on Exporting to Media (successful) At a minimum the audit system should collect media exportation events for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S mount -F auid>=1000 -F auid!=4294967295 -k export

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S mount -F auid>=1000 -F auid!=4294967295 -k export

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 Test attestation on 20121024 by DS The unauthorized exportation of data to external media could result in an information leak where classified information, Privacy Act information, and intellectual property could be lost. An audit trail should be created each time a filesystem is mounted to help identify and guard against information loss. CCE-RHEL7-CCE-TBD To verify that auditing is configured for all media exportation events, run the following command:

$ sudo auditctl -l | grep syscall | grep mount

Ensure auditd Collects File Deletion Events by User At a minimum the audit system should collect file deletion events for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 172 468 Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as, detecting malicious processes that attempt to delete log files to conceal their presence. CCE-27206-2 To determine if the system is configured to audit calls to the unlink system call, run the following command:

$ sudo grep "unlink" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the unlinkat system call, run the following command:

$ sudo grep "unlinkat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the rename system call, run the following command:

$ sudo grep "rename" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the renameat system call, run the following command:

$ sudo grep "renameat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Ensure auditd Collects System Administrator Actions At a minimum the audit system should collect administrator actions for all users and root. If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d:

-w /etc/sudoers -p wa -k actions

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file:

-w /etc/sudoers -p wa -k actions

AC-2(7)(b) AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 126 Test attestation on 20121024 by DS The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes. CCE-RHEL7-CCE-TBD To verify that auditing is configured for system administrator actions, run the following command:

$ sudo auditctl -l | grep "watch=/etc/sudoers"

Ensure auditd Collects Information on Kernel Module Loading and Unloading If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system:

-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-a always,exit -F arch=ARCH -S init_module -S delete_module -k modules

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file in order to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system:

-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-a always,exit -F arch=ARCH -S init_module -S delete_module -k modules

AC-17(7) AU-1(b) AU-2(a) AU-2(c) AU-2(d) AU-12(a) AU-12(c) IR-5 172 477 The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel. CCE-27129-6 To determine if the system is configured to audit calls to the init_module system call, run the following command:

$ sudo grep "init_module" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the delete_module system call, run the following command:

$ sudo grep "delete_module" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. Make the auditd Configuration Immutable If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following line to a file with suffix .rules in the directory /etc/audit/rules.d in order to make the auditd configuration immutable:

-e 2

If the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following line to /etc/audit/audit.rules file in order to make the auditd configuration immutable:

-e 2

With this setting, a reboot will be required to change any audit rules. AC-6 AU-1(b) AU-2(a) AU-2(c) AU-2(d) IR-5 Making the audit configuration immutable prevents accidental as well as malicious modification of the audit rules, although it may be problematic if legitimate changes are needed during system operation CCE-27097-5 Services The best protection against vulnerable software is running less software. This section describes how to review the software which Red Hat Enterprise Linux 7 installs on a system and disable software which is not needed. It then enumerates the software packages installed on a default RHEL 7 system and provides guidance about which ones can be safely disabled.

RHEL 7 provides a convenient minimal install option that essentially installs the bare necessities for a functional system. When building RHEL 7 servers, it is highly recommended to select the minimal packages and then build up the system from there. Obsolete Services This section discusses a number of network-visible services which have historically caused problems for system security, and for which disabling or severely limiting the service has been the best available guidance for some time. As a result of this, many of these services are not installed as part of RHEL 7 by default.

Organizations which are running these services should switch to more secure equivalents as soon as possible. If it remains absolutely necessary to run one of these services for legacy reasons, care should be taken to restrict the service as much as possible, for instance by configuring host firewall software such as iptables to restrict access to the vulnerable service to only those remote hosts which have a known need to use it. Xinetd The xinetd service acts as a dedicated listener for some network services (mostly, obsolete ones) and can be used to provide access controls and perform some logging. It has been largely obsoleted by other features, and it is not installed by default. The older Inetd service is not even available as part of RHEL 7. Disable xinetd Service The xinetd service can be disabled with the following command:

$ sudo systemctl disable xinetd

AC-17(8) CM-7 305 Test attestation on 20121026 by DS The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself. CCE-RHEL7-CCE-TBD If network services are using the xinetd service, this is not applicable.

To check that the xinetd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled xinetd

Output should indicate the xinetd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled xinetd
disabled

Run the following command to verify xinetd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active xinetd

If the service is not running the command will return the following output:

inactive

Uninstall xinetd Package The xinetd package can be uninstalled with the following command:

$ sudo yum erase xinetd

AC-17(8) CM-7 305 Test attestation on 20121026 by DS Removing the xinetd package decreases the risk of the xinetd service's accidental (or intentional) activation. CCE-RHEL7-CCE-TBD if rpm -qa | grep -q xinetd; then yum -y remove xinetd fi If network services are using the xinetd service, this is not applicable.

Run the following command to determine if the xinetd package is installed:

$ rpm -q xinetd

Telnet The telnet protocol does not provide confidentiality or integrity for information transmitted on the network. This includes authentication information such as passwords. Organizations which use telnet should be actively working to migrate to a more secure protocol. Disable telnet Service The telnet service configuration file /etc/xinetd.d/telnet is not created automatically. If it was created manually, check the /etc/xinetd.d/telnet file and ensure that disable = no is changed to read disable = yes as follows below:


# description: The telnet server serves telnet sessions; it uses \\
#       unencrypted username/password pairs for authentication.
service telnet
{
        flags           = REUSE
        socket_type     = stream

        wait            = no
        user            = root
        server          = /usr/sbin/in.telnetd
        log_on_failure  += USERID
        disable         = yes
}

Then the activation of the telnet service on system boot can be disabled via the following command:

# systemctl disable telnet.socket

AC-17(8) CM-7 IA-5(1)(c) Test attestation on 20140922 by JL The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks. CCE-27158-5 To check that the telnet service is disabled in system boot configuration, run the following command:

$ chkconfig telnet --list

Output should indicate the telnet service has either not been installed, or has been disabled, as shown in the example below:

$ chkconfig telnet --list

                         Note: This output shows SysV services only and does not include native
                         systemd services. SysV configuration data might be overridden by native
                         systemd configuration.

                         If you want to list systemd services use 'systemctl list-unit-files'.
                         To see services enabled on particular target use
                         'systemctl list-dependencies [target]'.

                         telnet       off

Uninstall telnet-server Package The telnet-server package can be uninstalled with the following command:

$ sudo yum erase telnet-server

AC-17(8) CM-7 Test attestation on 20121026 by DS Removing the telnet-server package decreases the risk of the telnet service's accidental (or intentional) activation. CCE-27165-0 if rpm -qa | grep -q telnet-server; then yum -y remove telnet-server fi Run the following command to determine if the telnet-server package is installed:

$ rpm -q telnet-server

Remove telnet Clients The telnet client allows users to start connections to other systems via the telnet protocol. The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in Red Hat Enterprise Linux. CCE-27039-7 yum -y remove telnet The telnet package can be removed with the following command:

$ sudo yum erase telnet

Rlogin, Rsh, and Rexec The Berkeley r-commands are legacy services which allow cleartext remote access and have an insecure trust model. Uninstall rsh-server Package The rsh-server package can be uninstalled with the following command:

$ sudo yum erase rsh-server

AC-17(8) CM-7 305 381 Test attestation on 20121026 by DS The rsh-server package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation. CCE-RHEL7-CCE-TBD yum -y erase rsh-server Run the following command to determine if the rsh-server package is installed:

$ rpm -q rsh-server

Disable rexec Service The rexec service, which is available with the rsh-server package and runs as a service through xinetd, should be disabled. The rexec service can be disabled with the following command:

$ sudo systemctl disable rexec

AC-17(8) CM-7 68 1436 Test attestation on 20121026 by DS The rexec service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. CCE-RHEL7-CCE-TBD To check that the rexec service is disabled in system boot configuration, run the following command:

$ chkconfig rexec --list

Output should indicate the rexec service has either not been installed, or has been disabled, as shown in the example below:

$ chkconfig rexec --list

                         Note: This output shows SysV services only and does not include native
                         systemd services. SysV configuration data might be overridden by native
                         systemd configuration.

                         If you want to list systemd services use 'systemctl list-unit-files'.
                         To see services enabled on particular target use
                         'systemctl list-dependencies [target]'.

                         rexec       off

Disable rsh Service The rsh service, which is available with the rsh-server package and runs as a service through xinetd, should be disabled. The rsh service can be disabled with the following command:

$ sudo systemctl disable rsh

AC-17(8) CM-7 IA-5(1)(c) 68 1436 Test attestation on 20121026 by DS The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. CCE-RHEL7-CCE-TBD To check that the rsh service is disabled in system boot configuration, run the following command:

$ chkconfig rsh --list

Output should indicate the rsh service has either not been installed, or has been disabled, as shown in the example below:

$ chkconfig rsh --list

                         Note: This output shows SysV services only and does not include native
                         systemd services. SysV configuration data might be overridden by native
                         systemd configuration.

                         If you want to list systemd services use 'systemctl list-unit-files'.
                         To see services enabled on particular target use
                         'systemctl list-dependencies [target]'.

                         rsh       off

Uninstal rsh Package The rsh package contains the client commands for the rsh services Test attestation on 20140530 by JL These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh,rcp, and rlogin. CCE- The rsh package can be removed with the following command:

$ sudo yum erase rsh

Disable rlogin Service The rlogin service, which is available with the rsh-server package and runs as a service through xinetd, should be disabled. The rlogin service can be disabled with the following command:

$ sudo systemctl disable rlogin

AC-17(8) CM-7 IA-5(1)(c) 1436 Test attestation on 20121026 by DS The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. CCE-RHEL7-CCE-TBD To check that the rlogin service is disabled in system boot configuration, run the following command:

$ chkconfig rlogin --list

Output should indicate the rlogin service has either not been installed, or has been disabled, as shown in the example below:

$ chkconfig rlogin --list

                         Note: This output shows SysV services only and does not include native
                         systemd services. SysV configuration data might be overridden by native
                         systemd configuration.

                         If you want to list systemd services use 'systemctl list-unit-files'.
                         To see services enabled on particular target use
                         'systemctl list-dependencies [target]'.

                         rlogin       off

Remove Rsh Trust Files The files /etc/hosts.equiv and ~/.rhosts (in each user's home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location:

$ sudo rm /etc/hosts.equiv

$ rm ~/.rhosts

AC-17(8) CM-7 1436 Test attestation on 20121026 by DS Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system. CCE-RHEL7-CCE-TBD find -type f -name .rhosts -exec rm -f '{}' \; rm /etc/hosts.equiv The existence of the file /etc/hosts.equiv or a file named .rhosts inside a user home directory indicates the presence of an Rsh trust relationship. NIS The Network Information Service (NIS), also known as 'Yellow Pages' (YP), and its successor NIS+ have been made obsolete by Kerberos, LDAP, and other modern centralized authentication services. NIS should not be used because it suffers from security problems inherent in its design, such as inadequate protection of important authentication information. Uninstall ypserv Package The ypserv package can be uninstalled with the following command:

$ sudo yum erase ypserv

AC-17(8) CM-7 305 381 Test attestation on 20121026 by DS Removing the ypserv package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services. CCE-RHEL7-CCE-TBD if rpm -qa | grep -q ypserv; then yum -y remove ypserv fi Run the following command to determine if the ypserv package is installed:

$ rpm -q ypserv

Disable ypbind Service The ypbind service, which allows the system to act as a client in a NIS or NIS+ domain, should be disabled. The ypbind service can be disabled with the following command:

$ sudo systemctl disable ypbind

AC-17(8) CM-7 305 Test attestation on 20121026 by DS Disabling the ypbind service ensures the system is not acting as a client in a NIS or NIS+ domain. CCE-RHEL7-CCE-TBD To check that the ypbind service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled ypbind

Output should indicate the ypbind service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled ypbind
disabled

Run the following command to verify ypbind is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active ypbind

If the service is not running the command will return the following output:

inactive

Remove NIS Client The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files. The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed. CCE- The ypbind package can be removed with the following command:

$ sudo yum erase ypbind

TFTP Server TFTP is a lightweight version of the FTP protocol which has traditionally been used to configure networking equipment. However, TFTP provides little security, and modern versions of networking operating systems frequently support configuration via SSH or other more secure protocols. A TFTP server should be run only if no more secure method of supporting existing equipment can be found. Disable tftp Service The tftp service should be disabled. The tftp service can be disabled with the following command:

$ sudo systemctl disable tftp

AC-17(8) CM-7 1436 Test attestation on 20121026 by DS Disabling the tftp service ensures the system is not acting as a TFTP server, which does not provide encryption or authentication. CCE-RHEL7-CCE-TBD To check that the tftp service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled tftp

Output should indicate the tftp service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled tftp
disabled

Run the following command to verify tftp is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active tftp

If the service is not running the command will return the following output:

inactive

Uninstall tftp-server Package The tftp-server package can be removed with the following command:

$ sudo yum erase tftp-server

AC-17(8) CM-7 305 Test attestation on 20121026 by DS Removing the tftp-server package decreases the risk of the accidental (or intentional) activation of tftp services. CCE-RHEL7-CCE-TBD Run the following command to determine if the tftp-server package is installed:

$ rpm -q tftp-server

Remove tftp Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot files between machines. TFTP does not support authentication and can be easily hacked. The package tftp is a client program that allows for connections to a tftp server. It is recommended that TFTP be remvoed, unless there is a specific need for TFTP (such as a boot server). In that case, use extreme caution when configuring the services. CCE- The tftp package can be removed with the following command:

$ sudo yum erase tftp

Ensure tftp Daemon Uses Secure Mode If running the tftp service is necessary, it should be configured to change its root directory at startup. To do so, ensure /etc/xinetd.d/tftp includes -s as a command line argument, as shown in the following example (which is also the default):

server_args = -s /var/lib/tftpboot

AC-17(8) CM-7 366 Using the -s option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally-specified directory reduces the risk of sharing files which should remain private. CCE-RHEL7-CCE-TBD If TFTP is not installed, this is not applicable. To determine if TFTP is installed, run the following command:

$ rpm -qa | grep tftp



Verify tftp is configured by with the -s option by running the following command:

grep "server_args" /etc/xinetd.d/tftp

The output should indicate the server_args variable is configured with the -s flag, matching the example below:

$ grep "server_args" /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

Chat/Messaging Services The talk software makes it possible for users to send and receive messages across systems through a terminal session. Uninstall talk-server Package The talk-server package can be removed with the following command:

$ sudo yum erase talk-server

Test attestation on 20140625 by JL The talk software presents a security risk as it uses unencrypted protocols for communications. Removing the talk-server package decreases the risk of the accidental (or intentional) activation of talk services. CCE- Run the following command to determine if the talk-server package is installed:

$ rpm -q talk-server

Uninstall talk Package The talk package contains the client program for the Internet talk protocol, which allows the user to chat with other users on different systems. Talk is a communication program which copies lines from one terminal to the terminal of another user. Test attestation on 20140625 by JL The talk software presents a security risk as it uses unencrypted protocols for communications. Removing the talk package decreases the risk of the accidental (or intentional) activation of talk client program. CCE- The talk package can be removed with the following command:

$ sudo yum erase talk

Base Services This section addresses the base services that are installed on a RHEL 7 default installation which are not covered in other sections. Some of these services listen on the network and should be treated with particular discretion. Other services are local system utilities that may or may not be extraneous. In general, system services should be disabled if not required. Disable Automatic Bug Reporting Tool (abrtd) The Automatic Bug Reporting Tool (abrtd) daemon collects and reports crash data when an application crash is detected. Using a variety of plugins, abrtd can email crash reports to system administrators, log crash reports to files, or forward crash reports to a centralized issue tracking system such as RHTSupport. The abrtd service can be disabled with the following command:

$ sudo systemctl disable abrtd

AC-17(8) CM-7 Test attestation on 20140921 by JL Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process's address space or registers. CCE-26872-2 # # Disable abrtd.service for all systemd targets # systemctl disable abrtd.service # # Stop abrtd.service if currently running # systemctl stop abrtd.service To check that the abrtd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled abrtd

Output should indicate the abrtd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled abrtd
disabled

Run the following command to verify abrtd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active abrtd

If the service is not running the command will return the following output:

inactive

Disable Advanced Configuration and Power Interface (acpid) The Advanced Configuration and Power Interface Daemon (acpid) dispatches ACPI events (such as power/reset button depressed) to userspace programs. The acpid service can be disabled with the following command:

$ sudo systemctl disable acpid

CM-7 ACPI support is highly desirable for systems in some network roles, such as laptops or desktops. For other systems, such as servers, it may permit accidental or trivially achievable denial of service situations and disabling it is appropriate. CCE-RHEL7-CCE-TBD # # Disable acpid.service for all systemd targets # systemctl disable acpid.service # # Stop acpid.service if currently running # systemctl stop acpid.service To check that the acpid service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled acpid

Output should indicate the acpid service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled acpid
disabled

Run the following command to verify acpid is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active acpid

If the service is not running the command will return the following output:

inactive

Disable Certmonger Service (certmonger) Certmonger is a D-Bus based service that attempts to simplify interaction with certifying authorities on networks which use public-key infrastructure. It is often combined with Red Hat's IPA (Identity Policy Audit) security information management solution to aid in the management of certificates. The certmonger service can be disabled with the following command:

$ sudo systemctl disable certmonger

CM-7 The services provided by certmonger may be essential for systems fulfilling some roles a PKI infrastructure, but its functionality is not necessary for many other use cases. CCE-RHEL7-CCE-TBD # # Disable certmonger.service for all systemd targets # systemctl disable certmonger.service # # Stop certmonger.service if currently running # systemctl stop certmonger.service To check that the certmonger service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled certmonger

Output should indicate the certmonger service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled certmonger
disabled

Run the following command to verify certmonger is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active certmonger

If the service is not running the command will return the following output:

inactive

Disable Control Group Config (cgconfig) Control groups allow an administrator to allocate system resources (such as CPU, memory, network bandwidth, etc) among a defined group (or groups) of processes executing on a system. The cgconfig daemon starts at boot and establishes the predefined control groups. The cgconfig service can be disabled with the following command:

$ sudo systemctl disable cgconfig

CM-7 Unless control groups are used to manage system resources, running the cgconfig service is not necessary. CCE-RHEL7-CCE-TBD # # Disable cgconfig.service for all systemd targets # systemctl disable cgconfig.service # # Stop cgconfig.service if currently running # systemctl stop cgconfig.service To check that the cgconfig service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled cgconfig

Output should indicate the cgconfig service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled cgconfig
disabled

Run the following command to verify cgconfig is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active cgconfig

If the service is not running the command will return the following output:

inactive

Disable Control Group Rules Engine (cgred) The cgred service moves tasks into control groups according to parameters set in the /etc/cgrules.conf configuration file. The cgred service can be disabled with the following command:

$ sudo systemctl disable cgred

CM-7 Unless control groups are used to manage system resources, running the cgred service service is not necessary. CCE-RHEL7-CCE-TBD # # Disable cgred.service for all systemd targets # systemctl disable cgred.service # # Stop cgred.service if currently running # systemctl stop cgred.service To check that the cgred service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled cgred

Output should indicate the cgred service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled cgred
disabled

Run the following command to verify cgred is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active cgred

If the service is not running the command will return the following output:

inactive

Disable CPU Speed (cpuspeed) The cpuspeed service can adjust the clock speed of supported CPUs based upon the current processing load thereby conserving power and reducing heat. The cpuspeed service can be disabled with the following command:

$ sudo systemctl disable cpuspeed

CM-7 The cpuspeed service is only necessary if adjusting the CPU clock speed provides benefit. Traditionally this has included laptops (to enhance battery life), but may also apply to server or desktop environments where conserving power is highly desirable or necessary. CCE-RHEL7-CCE-TBD To check that the cpuspeed service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled cpuspeed

Output should indicate the cpuspeed service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled cpuspeed
disabled

Run the following command to verify cpuspeed is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active cpuspeed

If the service is not running the command will return the following output:

inactive

Enable IRQ Balance (irqbalance) The irqbalance service optimizes the balance between power savings and performance through distribution of hardware interrupts across multiple processors. The irqbalance service can be enabled with the following command:

$ sudo systemctl enable irqbalance

CM-7 In an environment with multiple processors (now common), the irqbalance service provides potential speedups for handling interrupt requests. CCE-RHEL7-CCE-TBD # # Enable irqbalance.service for all systemd targets # systemctl enable irqbalance.service # # Start irqbalance.service if not currently running # systemctl start irqbalance.service To check that the irqbalance service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled irqbalance

Output should indicate the irqbalance service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled irqbalance
disabled

Run the following command to verify irqbalance is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active irqbalance

If the service is not running the command will return the following output:

inactive

Disable KDump Kernel Crash Analyzer (kdump) The kdump service provides a kernel crash dump analyzer. It uses the kexec system call to boot a secondary kernel ("capture" kernel) following a system crash, which can load information from the crashed kernel for analysis. The kdump service can be disabled with the following command:

$ sudo systemctl disable kdump

AC-17(8) CM-7 Unless the system is used for kernel development or testing, there is little need to run the kdump service. CCE-RHEL7-CCE-TBD # # Disable kdump.service for all systemd targets # systemctl disable kdump.service # # Stop kdump.service if currently running # systemctl stop kdump.service To check that the kdump service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled kdump

Output should indicate the kdump service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled kdump
disabled

Run the following command to verify kdump is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active kdump

If the service is not running the command will return the following output:

inactive

Disable Software RAID Monitor (mdmonitor) The mdmonitor service is used for monitoring a software RAID array; hardware RAID setups do not use this service. The mdmonitor service can be disabled with the following command:

$ sudo systemctl disable mdmonitor

CM-7 If software RAID monitoring is not required, there is no need to run this service. CCE-RHEL7-CCE-TBD # # Disable mdmonitor.service for all systemd targets # systemctl disable mdmonitor.service # # Stop mdmonitor.service if currently running # systemctl stop mdmonitor.service To check that the mdmonitor service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled mdmonitor

Output should indicate the mdmonitor service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled mdmonitor
disabled

Run the following command to verify mdmonitor is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active mdmonitor

If the service is not running the command will return the following output:

inactive

Disable D-Bus IPC Service (messagebus) D-Bus provides an IPC mechanism used by a growing list of programs, such as those used for Gnome, Bluetooth, and Avahi. Due to these dependencies, disabling D-Bus may not be practical for many systems. The messagebus service can be disabled with the following command:

$ sudo systemctl disable messagebus

CM-7 If no services which require D-Bus are needed, then it can be disabled. As a broker for IPC between processes of different privilege levels, it could be a target for attack. However, disabling D-Bus is likely to be impractical for any system which needs to provide a graphical login session. CCE-RHEL7-CCE-TBD # # Disable messagebus.service for all systemd targets # systemctl disable messagebus.service # # Stop messagebus.service if currently running # systemctl stop messagebus.service To check that the messagebus service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled messagebus

Output should indicate the messagebus service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled messagebus
disabled

Run the following command to verify messagebus is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active messagebus

If the service is not running the command will return the following output:

inactive

Disable Network Console (netconsole) The netconsole service is responsible for loading the netconsole kernel module, which logs kernel printk messages over UDP to a syslog server. This allows debugging of problems where disk logging fails and serial consoles are impractical. The netconsole service can be disabled with the following command:

$ sudo systemctl disable netconsole

AC-17(8) CM-7 381 The netconsole service is not necessary unless there is a need to debug kernel panics, which is not common. CCE-RHEL7-CCE-TBD # # Disable netconsole for all run levels # chkconfig --level 0123456 netconsole off # # Stop netconsole if currently running # service netconsole stop To check that the netconsole service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled netconsole

Output should indicate the netconsole service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled netconsole
disabled

Run the following command to verify netconsole is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active netconsole

If the service is not running the command will return the following output:

inactive

Disable ntpdate Service (ntpdate) The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in /etc/ntp/step-tickers or /etc/ntp.conf and then sets the local hardware clock to the newly synchronized system time. The ntpdate service can be disabled with the following command:

$ sudo systemctl disable ntpdate

AC-17(8) CM-7 382 Test attestation on 20121024 by DS The ntpdate service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated. CCE-RHEL7-CCE-TBD To check that the ntpdate service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled ntpdate

Output should indicate the ntpdate service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled ntpdate
disabled

Run the following command to verify ntpdate is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active ntpdate

If the service is not running the command will return the following output:

inactive

Disable Odd Job Daemon (oddjobd) The oddjobd service exists to provide an interface and access control mechanism through which specified privileged tasks can run tasks for unprivileged client applications. Communication with oddjobd through the system message bus. The oddjobd service can be disabled with the following command:

$ sudo systemctl disable oddjobd

CM-7 381 Test attestation on 20121024 by DS The oddjobd service may provide necessary functionality in some environments, and can be disabled if it is not needed. Execution of tasks by privileged programs, on behalf of unprivileged ones, has traditionally been a source of privilege escalation security issues. CCE-RHEL7-CCE-TBD # # Disable oddjobd.service for all systemd targets # systemctl disable oddjobd.service # # Stop oddjobd.service if currently running # systemctl stop oddjobd.service To check that the oddjobd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled oddjobd

Output should indicate the oddjobd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled oddjobd
disabled

Run the following command to verify oddjobd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active oddjobd

If the service is not running the command will return the following output:

inactive

Disable Portreserve (portreserve) The portreserve service is a TCP port reservation utility that can be used to prevent portmap from binding to well known TCP ports that are required for other services. The portreserve service can be disabled with the following command:

$ sudo systemctl disable portreserve

AC-17(8) CM-7 Test attestation on 20121024 by DS The portreserve service provides helpful functionality by preventing conflicting usage of ports in the reserved port range, but it can be disabled if not needed. CCE-RHEL7-CCE-TBD # # Disable portreserve.service for all systemd targets # systemctl disable portreserve.service # # Stop portreserve.service if currently running # systemctl stop portreserve.service To check that the portreserve service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled portreserve

Output should indicate the portreserve service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled portreserve
disabled

Run the following command to verify portreserve is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active portreserve

If the service is not running the command will return the following output:

inactive

Enable Process Accounting (psacct) The process accounting service, psacct, works with programs including acct and ac to allow system administrators to view user activity, such as commands issued by users of the system. The psacct service can be enabled with the following command:

$ sudo systemctl enable psacct

AU-12 CM-7 Test attestation on 20121024 by DS The psacct service can provide administrators a convenient view into some user activities. However, it should be noted that the auditing system and its audit records provide more authoritative and comprehensive records. CCE-RHEL7-CCE-TBD # # Enable psacct.service for all systemd targets # systemctl enable psacct.service # # Start psacct.service if not currently running # systemctl start psacct.service To check that the psacct service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled psacct

Output should indicate the psacct service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled psacct
disabled

Run the following command to verify psacct is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active psacct

If the service is not running the command will return the following output:

inactive

Disable Apache Qpid (qpidd) The qpidd service provides high speed, secure, guaranteed delivery services. It is an implementation of the Advanced Message Queuing Protocol. By default the qpidd service will bind to port 5672 and listen for connection attempts. The qpidd service can be disabled with the following command:

$ sudo systemctl disable qpidd

AC-17(8) CM-7 382 The qpidd service is automatically installed when the "base" package selection is selected during installation. The qpidd service listens for network connections, which increases the attack surface of the system. If the system is not intended to receive AMQP traffic, then the qpidd service is not needed and should be disabled or removed. CCE-RHEL7-CCE-TBD # # Disable qpidd.service for all systemd targets # systemctl disable qpidd.service # # Stop qpidd.service if currently running # systemctl stop qpidd.service To check that the qpidd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled qpidd

Output should indicate the qpidd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled qpidd
disabled

Run the following command to verify qpidd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active qpidd

If the service is not running the command will return the following output:

inactive

Disable Quota Netlink (quota_nld) The quota_nld service provides notifications to users of disk space quota violations. It listens to the kernel via a netlink socket for disk quota violations and notifies the appropriate user of the violation using D-Bus or by sending a message to the terminal that the user has last accessed. The quota_nld service can be disabled with the following command:

$ sudo systemctl disable quota_nld

CM-7 Test attestation on 20121024 by DS If disk quotas are enforced on the local system, then the quota_nld service likely provides useful functionality and should remain enabled. However, if disk quotas are not used or user notification of disk quota violation is not desired then there is no need to run this service. CCE-RHEL7-CCE-TBD # # Disable quota_nld.service for all systemd targets # systemctl disable quota_nld.service # # Stop quota_nld.service if currently running # systemctl stop quota_nld.service To check that the quota_nld service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled quota_nld

Output should indicate the quota_nld service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled quota_nld
disabled

Run the following command to verify quota_nld is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active quota_nld

If the service is not running the command will return the following output:

inactive

Disable Network Router Discovery Daemon (rdisc) The rdisc service implements the client side of the ICMP Internet Router Discovery Protocol (IRDP), which allows discovery of routers on the local subnet. If a router is discovered then the local routing table is updated with a corresponding default route. By default this daemon is disabled. The rdisc service can be disabled with the following command:

$ sudo systemctl disable rdisc

AC-17(8) AC-4 CM-7 382 Test attestation on 20121024 by DS General-purpose systems typically have their network and routing information configured statically by a system administrator. Workstations or some special-purpose systems often use DHCP (instead of IRDP) to retrieve dynamic network configuration information. CCE-RHEL7-CCE-TBD # # Disable rdisc.service for all systemd targets # systemctl disable rdisc.service # # Stop rdisc.service if currently running # systemctl stop rdisc.service To check that the rdisc service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled rdisc

Output should indicate the rdisc service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled rdisc
disabled

Run the following command to verify rdisc is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active rdisc

If the service is not running the command will return the following output:

inactive

Disable Red Hat Network Service (rhnsd) The Red Hat Network service automatically queries Red Hat Network servers to determine whether there are any actions that should be executed, such as package updates. This only occurs if the system was registered to an RHN server or satellite and managed as such. The rhnsd service can be disabled with the following command:

$ sudo systemctl disable rhnsd

AC-17(8) CM-7 382 Test attestation on 20121024 by DS Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system is being managed by RHN or RHN Satellite Server the rhnsd daemon can remain on. CCE-RHEL7-CCE-TBD # # Disable rhnsd for all run levels # chkconfig --level 0123456 rhnsd off # # Stop rhnsd if currently running # service rhnsd stop To check that the rhnsd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled rhnsd

Output should indicate the rhnsd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled rhnsd
disabled

Run the following command to verify rhnsd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active rhnsd

If the service is not running the command will return the following output:

inactive

Disable Red Hat Subscription Manager Daemon (rhsmcertd) The Red Hat Subscription Manager (rhsmcertd) periodically checks for changes in the entitlement certificates for a registered system and updates it accordingly. The rhsmcertd service can be disabled with the following command:

$ sudo systemctl disable rhsmcertd

CM-7 Test attestation on 20121024 by DS The rhsmcertd service can provide administrators with some additional control over which of their systems are entitled to particular subscriptions. However, for systems that are managed locally or which are not expected to require remote changes to their subscription status, it is unnecessary and can be disabled. CCE-RHEL7-CCE-TBD # # Disable rhsmcertd.service for all systemd targets # systemctl disable rhsmcertd.service # # Stop rhsmcertd.service if currently running # systemctl stop rhsmcertd.service To check that the rhsmcertd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled rhsmcertd

Output should indicate the rhsmcertd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled rhsmcertd
disabled

Run the following command to verify rhsmcertd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active rhsmcertd

If the service is not running the command will return the following output:

inactive

Disable Cyrus SASL Authentication Daemon (saslauthd) The saslauthd service handles plaintext authentication requests on behalf of the SASL library. The service isolates all code requiring superuser privileges for SASL authentication into a single process, and can also be used to provide proxy authentication services to clients that do not understand SASL based authentication. The saslauthd service can be disabled with the following command:

$ sudo systemctl disable saslauthd

AC-17(8) CM-7 Test attestation on 20121024 by DS The saslauthd service provides essential functionality for performing authentication in some directory environments, such as those which use Kerberos and LDAP. For others, however, in which only local files may be consulted, it is not necessary and should be disabled. CCE-RHEL7-CCE-TBD # # Disable saslauthd.service for all systemd targets # systemctl disable saslauthd.service # # Stop saslauthd.service if currently running # systemctl stop saslauthd.service To check that the saslauthd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled saslauthd

Output should indicate the saslauthd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled saslauthd
disabled

Run the following command to verify saslauthd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active saslauthd

If the service is not running the command will return the following output:

inactive

Disable SMART Disk Monitoring Service (smartd) SMART (Self-Monitoring, Analysis, and Reporting Technology) is a feature of hard drives that allows them to detect symptoms of disk failure and relay an appropriate warning. The smartd service can be disabled with the following command:

$ sudo systemctl disable smartd

CM-7 Test attestation on 20121024 by DS SMART can help protect against denial of service due to failing hardware. Nevertheless, if it is not needed or the system's drives are not SMART-capable (such as solid state drives), it can be disabled. CCE-RHEL7-CCE-TBD # # Disable smartd.service for all systemd targets # systemctl disable smartd.service # # Stop smartd.service if currently running # systemctl stop smartd.service To check that the smartd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled smartd

Output should indicate the smartd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled smartd
disabled

Run the following command to verify smartd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active smartd

If the service is not running the command will return the following output:

inactive

Disable System Statistics Reset Service (sysstat) The sysstat service resets various I/O and CPU performance statistics to zero in order to begin counting from a fresh state at boot time. The sysstat service can be disabled with the following command:

$ sudo systemctl disable sysstat

CM-7 Test attestation on 20121024 by DS By default the sysstat service merely runs a program at boot to reset the statistics, which can be retrieved using programs such as sar and sadc. These may provide useful insight into system operation, but unless used this service can be disabled. CCE-RHEL7-CCE-TBD # # Disable sysstat.service for all systemd targets # systemctl disable sysstat.service # # Stop sysstat.service if currently running # systemctl stop sysstat.service To check that the sysstat service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled sysstat

Output should indicate the sysstat service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled sysstat
disabled

Run the following command to verify sysstat is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active sysstat

If the service is not running the command will return the following output:

inactive

Cron and At Daemons The cron and at services are used to allow commands to be executed at a later time. The cron service is required by almost all systems to perform necessary maintenance tasks, while at may or may not be required on a given system. Both daemons should be configured defensively. Enable cron Service The crond service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The crond service can be enabled with the following command:

$ sudo systemctl enable crond

CM-7 Test attestation on 20121024 by DS Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential. CCE-RHEL7-CCE-TBD # # Enable crond.service for all systemd targets # systemctl enable crond.service # # Start crond.service if not currently running # systemctl start crond.service Run the following command to determine the current status of the crond service:

$ systemctl is-active crond

If the service is running, it should return the following:

active

Disable anacron Service The cronie-anacron package, which provides anacron functionality, is installed by default. The cronie-anacron package can be removed with the following command:

$ sudo yum erase cronie-anacron

CM-7 The anacron service provides cron functionality for systems such as laptops and workstations that may be shut down during the normal times that cron jobs are scheduled to run. On systems which do not require this additional functionality, anacron could needlessly increase the possible attack surface for an intruder. CCE-RHEL7-CCE-TBD Run the following command to determine if the cronie-anacron package is installed:

$ rpm -q cronie-anacron

Disable At Service (atd) The at and batch commands can be used to schedule tasks that are meant to be executed only once. This allows delayed execution in a manner similar to cron, except that it is not recurring. The daemon atd keeps track of tasks scheduled via at and batch, and executes them at the specified time. The atd service can be disabled with the following command:

$ sudo systemctl disable atd

CM-7 381 The atd service could be used by an unsophisticated insider to carry out activities outside of a normal login session, which could complicate accountability. Furthermore, the need to schedule tasks with at or batch is not common. CCE-RHEL7-CCE-TBD # # Disable atd.service for all systemd targets # systemctl disable atd.service # # Stop atd.service if currently running # systemctl stop atd.service To check that the atd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled atd

Output should indicate the atd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled atd
disabled

Run the following command to verify atd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active atd

If the service is not running the command will return the following output:

inactive

Restrict at and cron to Authorized Users if Necessary The /etc/cron.allow and /etc/at.allow files contain lists of users who are allowed to use cron and at to delay execution of processes. If these files exist and if the corresponding files /etc/cron.deny and /etc/at.deny do not exist, then only users listed in the relevant allow files can run the crontab and at commands to submit jobs to be run at scheduled intervals. On many systems, only the system administrator needs the ability to schedule jobs. Note that even if a given user is not listed in cron.allow, cron jobs can still be run as that user. The cron.allow file controls only administrative access to the crontab command for scheduling and modifying cron jobs.

To restrict at and cron to only authorized users:

    Remove the cron.deny file:

    $ sudo rm /etc/cron.deny

    Edit /etc/cron.allow, adding one line for each user allowed to use the crontab command to create cron jobs.
    Remove the at.deny file:

    $ sudo rm /etc/at.deny

    Edit /etc/at.allow, adding one line for each user allowed to use the at command to create at jobs.

SSH Server The SSH protocol is recommended for remote login and remote file transfer. SSH provides confidentiality and integrity for data exchanged between two systems, as well as server authentication, through the use of public key cryptography. The implementation included with the system is called OpenSSH, and more detailed documentation is available from its website, http://www.openssh.org. Its server program is called sshd and provided by the RPM package openssh-server. SSH session Idle time Specify duration of allowed idle time. 300 300 600 900 3600 7200 Disable SSH Server If Possible (Unusual) The SSH server service, sshd, is commonly needed. However, if it can be disabled, do so. The sshd service can be disabled with the following command:

$ sudo systemctl disable sshd

This is unusual, as SSH is a common method for encrypted and authenticated remote access. Test attestation on 20121024 by DS CCE-RHEL7-CCE-TBD Remove SSH Server iptables Firewall exception (Unusual) By default, inbound connections to SSH's port are allowed. If the SSH server is not being used, this exception should be removed from the firewall configuration.

Edit the files /etc/sysconfig/iptables and /etc/sysconfig/ip6tables (if IPv6 is in use). In each file, locate and delete the line:

-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT

This is unusual, as SSH is a common method for encrypted and authenticated remote access. If inbound SSH connections are not expected, disallowing access to the SSH port will avoid possible exploitation of the port by an attacker. CCE-RHEL7-CCE-TBD Configure OpenSSH Server if Necessary If the system needs to act as an SSH server, then certain changes should be made to the OpenSSH daemon configuration file /etc/ssh/sshd_config. The following recommendations can be applied to this file. See the sshd_config(5) man page for more detailed information. Allow Only SSH Protocol 2 Only SSH protocol version 2 connections should be permitted. The default setting in /etc/ssh/sshd_config is correct, and can be verified by ensuring that the following line appears:

Protocol 2

AC-17(7) IA-5(1)(c) Test attestation on 20121024 by DS SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used. CCE-27038-9 grep -qi ^Protocol /etc/ssh/sshd_config && \ sed -i "s/Protocol.*/Protocol 2/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "Protocol 2" >> /etc/ssh/sshd_config fi To check which SSH protocol version is allowed, run the following command:

$ sudo grep Protocol /etc/ssh/sshd_config

If configured properly, output should be

Protocol 2

Limit Users' SSH Access By default, the SSH configuration allows any user with an account to access the system. In order to specify the users that are allowed to login via SSH and deny all other users, add or correct the following line in the /etc/ssh/sshd_config file:

DenyUsers USER1 USER2

Where USER1 and USER2 are valid user names. AC-3 Specifying which accounts are allowed SSH access into the system reduces the possibility of unauthorized access to the system. CCE-RHEL7-CCE-TBD Set SSH Idle Timeout Interval SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out.

To set an idle timeout interval, edit the following line in /etc/ssh/sshd_config as follows:

ClientAliveInterval interval

The timeout interval is given in seconds. To have a timeout of 15 minutes, set interval to 900.

If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle. AC-2(5) SA-8 Test attestation on 20121024 by DS Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another. CCE-26611-4 sshd_idle_timeout_value="" grep -qi ^ClientAliveInterval /etc/ssh/sshd_config && \ sed -i "s/ClientAliveInterval.*/ClientAliveInterval $sshd_idle_timeout_value/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "ClientAliveInterval $sshd_idle_timeout_value" >> /etc/ssh/sshd_config fi Run the following command to see what the timeout interval is:

$ sudo grep ClientAliveInterval /etc/ssh/sshd_config

If properly configured, the output should be:

ClientAliveInterval 900

Set SSH Client Alive Count To ensure the SSH idle timeout occurs precisely when the ClientAliveCountMax is set, edit /etc/ssh/sshd_config as follows:

ClientAliveCountMax 0

AC-2(5) SA-8 Test attestation on 20121024 by DS This ensures a user login will be terminated as soon as the ClientAliveCountMax is reached. CCE-27066-0 grep -qi ^ClientAliveCountMax /etc/ssh/sshd_config && \ sed -i "s/ClientAliveCountMax.*/ClientAliveCountMax 0/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config fi To ensure the SSH idle timeout will occur when the ClientAliveCountMax is set, run the following command:

$ sudo grep ClientAliveCountMax /etc/ssh/sshd_config

If properly configured, output should be:

ClientAliveCountMax 0

Disable SSH Support for .rhosts Files SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via .rhosts files.

To ensure this behavior is disabled, add or correct the following line in /etc/ssh/sshd_config:

IgnoreRhosts yes

AC-3 SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. CCE-27035-5 grep -qi ^IgnoreRhosts /etc/ssh/sshd_config && \ sed -i "s/IgnoreRhosts.*/IgnoreRhosts yes/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config fi To determine how the SSH daemon's IgnoreRhosts option is set, run the following command:

$ sudo grep -i IgnoreRhosts /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value yes is returned, then the required value is set. Disable Host-Based Authentication SSH's cryptographic host-based authentication is more secure than .rhosts authentication. However, it is not recommended that hosts unilaterally trust one another, even within an organization.

To disable host-based authentication, add or correct the following line in /etc/ssh/sshd_config:

HostbasedAuthentication no

AC-3 Test attestation on 20121024 by DS SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. CCE-26870-6 grep -q ^HostbasedAuthentication /etc/ssh/sshd_config && \ sed -i "s/HostbasedAuthentication.*/HostbasedAuthentication no/g" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config fi To determine how the SSH daemon's HostbasedAuthentication option is set, run the following command:

$ sudo grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value no is returned, then the required value is set. Disable SSH Root Login The root user should never be allowed to login to a system directly over a network. To disable root login via SSH, add or correct the following line in /etc/ssh/sshd_config:

PermitRootLogin no

AC-3 AC-6(2) IA-2(1) Test attestation on 20121024 by DS Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password. CCE-26946-4 SSHD_CONFIG='/etc/ssh/sshd_config' # Obtain line number of first uncommented case-insensitive occurrence of Match # block directive (possibly prefixed with whitespace) present in $SSHD_CONFIG FIRST_MATCH_BLOCK=$(sed -n '/^[[:space:]]*Match[^\n]*/I{=;q}' $SSHD_CONFIG) # Obtain line number of first uncommented case-insensitive occurence of # PermitRootLogin directive (possibly prefixed with whitespace) present in # $SSHD_CONFIG FIRST_PERMIT_ROOT_LOGIN=$(sed -n '/^[[:space:]]*PermitRootLogin[^\n]*/I{=;q}' $SSHD_CONFIG) # Case: Match block directive not present in $SSHD_CONFIG if [ -z "$FIRST_MATCH_BLOCK" ] then # Case: PermitRootLogin directive not present in $SSHD_CONFIG yet if [ -z "$FIRST_PERMIT_ROOT_LOGIN" ] then # Append 'PermitRootLogin no' at the end of $SSHD_CONFIG echo -e "\nPermitRootLogin no" >> $SSHD_CONFIG # Case: PermitRootLogin directive present in $SSHD_CONFIG already else # Replace first uncommented case-insensitive occurrence # of PermitRootLogin directive sed -i "$FIRST_PERMIT_ROOT_LOGIN s/^[[:space:]]*PermitRootLogin.*$/PermitRootLogin no/I" $SSHD_CONFIG fi # Case: Match block directive present in $SSHD_CONFIG else # Case: PermitRootLogin directive not present in $SSHD_CONFIG yet if [ -z "$FIRST_PERMIT_ROOT_LOGIN" ] then # Prepend 'PermitRootLogin no' before first uncommented # case-insensitive occurrence of Match block directive sed -i "$FIRST_MATCH_BLOCK s/^\([[:space:]]*Match[^\n]*\)/PermitRootLogin no\n\1/I" $SSHD_CONFIG # Case: PermitRootLogin directive present in $SSHD_CONFIG and placed # before first Match block directive elif [ "$FIRST_PERMIT_ROOT_LOGIN" -lt "$FIRST_MATCH_BLOCK" ] then # Replace first uncommented case-insensitive occurrence # of PermitRootLogin directive sed -i "$FIRST_PERMIT_ROOT_LOGIN s/^[[:space:]]*PermitRootLogin.*$/PermitRootLogin no/I" $SSHD_CONFIG # Case: PermitRootLogin directive present in $SSHD_CONFIG and placed # after first Match block directive else # Prepend 'PermitRootLogin no' before first uncommented # case-insensitive occurrence of Match block directive sed -i "$FIRST_MATCH_BLOCK s/^\([[:space:]]*Match[^\n]*\)/PermitRootLogin no\n\1/I" $SSHD_CONFIG fi fi To determine how the SSH daemon's PermitRootLogin option is set, run the following command:

$ sudo grep -i PermitRootLogin /etc/ssh/sshd_config

If a line indicating no is returned, then the required value is set. Disable SSH Access via Empty Passwords To explicitly disallow remote login from accounts with empty passwords, add or correct the following line in /etc/ssh/sshd_config:

PermitEmptyPasswords no

Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords. AC-3 Test attestation on 20121024 by DS Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere. CCE-26864-9 grep -qi ^PermitEmptyPasswords /etc/ssh/sshd_config && \ sed -i "s/PermitEmptyPasswords.*/PermitEmptyPasswords no/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config fi To determine how the SSH daemon's PermitEmptyPasswords option is set, run the following command:

$ sudo grep -i PermitEmptyPasswords /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value no is returned, then the required value is set. Enable SSH Warning Banner To enable the warning banner and ensure it is consistent across the system, add or correct the following line in /etc/ssh/sshd_config:

Banner /etc/issue

Another section contains information on how to create an appropriate system-wide warning banner. AC-8(a) AC-8(c)(1) AC-8(c)(2) AC-8(c)(3) 1384 1385 1386 1387 1388 228 Test attestation on 20121024 by DS The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution. CCE-27314-4 grep -qi ^Banner /etc/ssh/sshd_config && \ sed -i "s/Banner.*/Banner \/etc\/issue/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "" >> /etc/ssh/sshd_config echo "Banner /etc/issue" >> /etc/ssh/sshd_config fi To determine how the SSH daemon's Banner option is set, run the following command:

$ sudo grep -i Banner /etc/ssh/sshd_config

If a line indicating /etc/issue is returned, then the required value is set. Do Not Allow SSH Environment Options To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in /etc/ssh/sshd_config:

PermitUserEnvironment no

Test attestation on 20121024 by DS SSH environment options potentially allow users to bypass access restriction in some configurations. CCE-26974-6 grep -qi ^PermitUserEnvironment /etc/ssh/sshd_config && \ sed -i "s/PermitUserEnvironment.*/PermitUserEnvironment no/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config fi To ensure users are not able to present environment daemons, run the following command:

$ sudo grep PermitUserEnvironment /etc/ssh/sshd_config

If properly configured, output should be:

PermitUserEnvironment no

Use Only Approved Ciphers Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. The following line in /etc/ssh/sshd_config demonstrates use of FIPS-approved ciphers:

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

The man page sshd_config(5) contains a list of supported ciphers. AC-3 AC-17(2) AU-10(5) IA-5(1)(c) IA-7 Test attestation on 20121024 by DS Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance. CCE-27051-2 grep -qi ^Ciphers /etc/ssh/sshd_config && \ sed -i "s/Ciphers.*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc/gI" /etc/ssh/sshd_config if ! [ $? -eq 0 ]; then echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config fi Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command:

$ sudo grep Ciphers /etc/ssh/sshd_config

The output should contain only those ciphers which are FIPS-approved, namely, the AES and 3DES ciphers. Strengthen Firewall Configuration if Possible If the SSH server is expected to only receive connections from the local network, then strengthen the default firewall rule for the SSH service to only accept connections from the appropriate network segment(s).

Determine an appropriate network block, netwk, and network mask, mask, representing the machines on your network which will be allowed to access this SSH server.

Edit the files etc/sysconfig/iptables and /etc/sysconfig/ip6tables (if IPv6 is in use). In each file, locate the line:

-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT

and replace it with:

-A INPUT -s netwk/mask -m state --state NEW -p tcp --dport 22 -j ACCEPT

Restricting SSH access to only trusted network segments reduces exposure of the SSH server to attacks from unauthorized networks. X Window System The X Window System implementation included with the system is called X.org. Disable X Windows Unless there is a mission-critical reason for the system to run a graphical user interface, ensure X is not set to start automatically at boot and remove the X Windows software packages. There is usually no reason to run X Windows on a dedicated server machine, as it increases the system's attack surface and consumes system resources. Administrators of server systems should instead login via SSH or on the text console. Disable X Windows Startup By Setting Default Target Setting the system's default target to multi-user will prevent automatic startup of the X server. To do so, run:

$ systemctl set-default multi-user.target

You should see the following output:

rm '/etc/systemd/system/default.target'
ln -s '/usr/lib/systemd/system/multi-user.target' '/etc/systemd/system/default.target'

AC-3 366 Test attestation on 20121025 by DS Unnecessary services should be disabled to decrease the attack surface of the system. CCE-RHEL7-CCE-TBD To verify the default target is multi-user, run the following command:

$ systemctl get-default

The output should show the following:

multi-user.target

Remove the X Windows Package Group Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command:

$ sudo yum groupremove "X Window System"

366 Test attestation on 20121025 by DS Unnecessary packages should not be installed to decrease the attack surface of the system. CCE-RHEL7-CCE-TBD To ensure the X Windows package group is removed, run the following command:

$ rpm -qi xorg-x11-server-common

The output should be:

package xorg-x11-server-common is not installed

Avahi Server The Avahi daemon implements the DNS Service Discovery and Multicast DNS protocols, which provide service and host discovery on a network. It allows a system to automatically identify resources on the network, such as printers or web servers. This capability is also known as mDNSresponder and is a major part of Zeroconf networking. Disable Avahi Server if Possible Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Disabling it can reduce the system's vulnerability to such attacks. Disable Avahi Server Software The avahi-daemon service can be disabled with the following command:

$ sudo systemctl disable avahi-daemon

CM-7 366 Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted. CCE-RHEL7-CCE-TBD To check that the avahi-daemon service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled avahi-daemon

Output should indicate the avahi-daemon service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled avahi-daemon
disabled

Run the following command to verify avahi-daemon is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active avahi-daemon

If the service is not running the command will return the following output:

inactive

Configure Avahi if Necessary If your system requires the Avahi daemon, its configuration can be restricted to improve security. The Avahi daemon configuration file is /etc/avahi/avahi-daemon.conf. The following security recommendations should be applied to this file: See the avahi-daemon.conf(5) man page, or documentation at http://www.avahi.org, for more detailed information about the configuration options. Serve Avahi Only via Required Protocol If you are using only IPv4, edit /etc/avahi/avahi-daemon.conf and ensure the following line exists in the [server] section:

use-ipv6=no

Similarly, if you are using only IPv6, disable IPv4 sockets with the line:

use-ipv4=no

CM-7 CCE-RHEL7-CCE-TBD Check Avahi Responses' TTL Field To make Avahi ignore packets unless the TTL field is 255, edit /etc/avahi/avahi-daemon.conf and ensure the following line appears in the [server] section:

check-response-ttl=yes

CM-7 This helps to ensure that only mDNS responses from the local network are processed, because the TTL field in a packet is decremented from its initial value of 255 whenever it is routed from one network to another. Although a properly-configured router or firewall should not allow mDNS packets into the local network at all, this option provides another check to ensure they are not permitted. CCE-RHEL7-CCE-TBD Prevent Other Programs from Using Avahi's Port To prevent other mDNS stacks from running, edit /etc/avahi/avahi-daemon.conf and ensure the following line appears in the [server] section:

disallow-other-stacks=yes

CM-7 This helps ensure that only Avahi is responsible for mDNS traffic coming from that port on the system. CCE-RHEL7-CCE-TBD Disable Avahi Publishing To prevent other mDNS stacks from running, edit /etc/avahi/avahi-daemon.conf and ensure the following line appears in the [server] section:

disallow-other-stacks=yes

CM-7 This helps ensure that only Avahi is responsible for mDNS traffic coming from that port on the system. CCE-RHEL7-CCE-TBD Restrict Information Published by Avahi If it is necessary to publish some information to the network, it should not be joined by any extraneous information, or by information supplied by a non-trusted source on the system. Prevent user applications from using Avahi to publish services by adding or correcting the following line in the [publish] section:

disable-user-service-publishing=yes

Implement as many of the following lines as possible, to restrict the information published by Avahi.

publish-addresses=no
publish-hinfo=no
publish-workstation=no
publish-domain=no

Inspect the files in the directory /etc/avahi/services/. Unless there is an operational need to publish information about each of these services, delete the corresponding file. CM-7 These options prevent publishing attempts from succeeding, and can be applied even if publishing is disabled entirely via disable-publishing. Alternatively, these can be used to restrict the types of published information in the event that some information must be published. CCE-RHEL7-CCE-TBD Print Support The Common Unix Printing System (CUPS) service provides both local and network printing support. A system running the CUPS service can accept print jobs from other systems, process them, and send them to the appropriate printer. It also provides an interface for remote administration through a web browser. The CUPS service is installed and activated by default. The project homepage and more detailed documentation are available at http://www.cups.org.

Disable the CUPS Service The cups service can be disabled with the following command:

$ sudo systemctl disable cups

CM-7 Turn off unneeded services to reduce attack surface. CCE-RHEL7-CCE-TBD # # Disable cups.service for all systemd targets # systemctl disable cups.service # # Stop cups.service if currently running # and disable cups.path and cups.socket so # cups.service can't be activated # systemctl stop cups.service systemctl disable cups.path systemctl disable cups.socket To check that the cups service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled cups

Output should indicate the cups service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled cups
disabled

Run the following command to verify cups is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active cups

If the service is not running the command will return the following output:

inactive

Configure the CUPS Service if Necessary CUPS provides the ability to easily share local printers with other machines over the network. It does this by allowing machines to share lists of available printers. Additionally, each machine that runs the CUPS service can potentially act as a print server. Whenever possible, the printer sharing and print server capabilities of CUPS should be limited or disabled. The following recommendations should demonstrate how to do just that. Disable Printer Browsing Entirely if Possible By default, CUPS listens on the network for printer list broadcasts on UDP port 631. This functionality is called printer browsing. To disable printer browsing entirely, edit the CUPS configuration file, located at /etc/cups/cupsd.conf, to include the following:

Browsing Off

CM-7 The CUPS print service can be configured to broadcast a list of available printers to the network. Other machines on the network, also running the CUPS print service, can be configured to listen to these broadcasts and add and configure these printers for immediate use. By disabling this browsing capability, the machine will no longer generate or receive such broadcasts. CCE-RHEL7-CCE-TBD Disable Print Server Capabilities To prevent remote users from potentially connecting to and using locally configured printers, disable the CUPS print server sharing capabilities. To do so, limit how the server will listen for print jobs by removing the more generic port directive from /etc/cups/cupsd.conf:

Port 631

and replacing it with the Listen directive:

Listen localhost:631

This will prevent remote users from printing to locally configured printers while still allowing local users on the machine to print normally. CM-7 By default, locally configured printers will not be shared over the network, but if this functionality has somehow been enabled, these recommendations will disable it again. Be sure to disable outgoing printer list broadcasts, or remote users will still be able to see the locally configured printers, even if they cannot actually print to them. To limit print serving to a particular set of users, use the Policy directive. CCE-RHEL7-CCE-TBD DHCP The Dynamic Host Configuration Protocol (DHCP) allows systems to request and obtain an IP address and other configuration parameters from a server.

This guide recommends configuring networking on clients by manually editing the appropriate files under /etc/sysconfig. Use of DHCP can make client systems vulnerable to compromise by rogue DHCP servers, and should be avoided unless necessary. If using DHCP is necessary, however, there are best practices that should be followed to minimize security risk. Disable DHCP Server The DHCP server dhcpd is not installed or activated by default. If the software was installed and activated, but the system does not need to act as a DHCP server, it should be disabled and removed. Disable DHCP Service The dhcpd service should be disabled on any system that does not need to act as a DHCP server. The dhcpd service can be disabled with the following command:

$ sudo systemctl disable dhcpd

CM-7 366 Test attestation on 20121024 by DS Unmanaged or unintentionally activated DHCP servers may provide faulty information to clients, interfering with the operation of a legitimate site DHCP server if there is one. CCE-RHEL7-CCE-TBD To check that the dhcpd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled dhcpd

Output should indicate the dhcpd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled dhcpd
disabled

Run the following command to verify dhcpd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active dhcpd

If the service is not running the command will return the following output:

inactive

Uninstall DHCP Server Package If the system does not need to act as a DHCP server, the dhcp package can be uninstalled. The dhcp package can be removed with the following command:

$ sudo yum erase dhcp

CM-7 366 Test attestation on 20121024 by DS Removing the DHCP server ensures that it cannot be easily or accidentally reactivated and disrupt network operation. CCE-RHEL7-CCE-TBD Run the following command to determine if the dhcp package is installed:

$ rpm -q dhcp

Disable DHCP Server If the system must act as a DHCP server, the configuration information it serves should be minimized. Also, support for other protocols and DNS-updating schemes should be explicitly disabled unless needed. The configuration file for dhcpd is called /etc/dhcp/dhcpd.conf. The file begins with a number of global configuration options. The remainder of the file is divided into sections, one for each block of addresses offered by dhcpd, each of which contains configuration options specific to that address block. Do Not Use Dynamic DNS To prevent the DHCP server from receiving DNS information from clients, edit /etc/dhcp/dhcpd.conf, and add or correct the following global option:

ddns-update-style none;

The ddns-update-style option controls only whether the DHCP server will attempt to act as a Dynamic DNS client. As long as the DNS server itself is correctly configured to reject DDNS attempts, an incorrect ddns-update-style setting on the client is harmless (but should be fixed as a best practice). CM-7 The Dynamic DNS protocol is used to remotely update the data served by a DNS server. DHCP servers can use Dynamic DNS to publish information about their clients. This setup carries security risks, and its use is not recommended. If Dynamic DNS must be used despite the risks it poses, it is critical that Dynamic DNS transactions be protected using TSIG or some other cryptographic authentication mechanism. See dhcpd.conf(5) for more information about protecting the DHCP server from passing along malicious DNS data from its clients. CCE-RHEL7-CCE-TBD Deny Decline Messages Edit /etc/dhcp/dhcpd.conf and add or correct the following global option to prevent the DHCP server from responding the DHCPDECLINE messages, if possible:

deny declines;

CM-7 The DHCPDECLINE message can be sent by a DHCP client to indicate that it does not consider the lease offered by the server to be valid. By issuing many DHCPDECLINE messages, a malicious client can exhaust the DHCP server's pool of IP addresses, causing the DHCP server to forget old address allocations. CCE-RHEL7-CCE-TBD Deny BOOTP Queries Unless your network needs to support older BOOTP clients, disable support for the bootp protocol by adding or correcting the global option:

deny bootp;

CM-7 The bootp option tells dhcpd to respond to BOOTP queries. If support for this simpler protocol is not needed, it should be disabled to remove attack vectors against the DHCP server. CCE-RHEL7-CCE-TBD Minimize Served Information Edit /etc/dhcp/dhcpd.conf. Examine each address range section within the file, and ensure that the following options are not defined unless there is an operational need to provide this information via DHCP:

option domain-name
option domain-name-servers
option nis-domain
option nis-servers
option ntp-servers
option routers
option time-offset

By default, the RHEL client installation uses DHCP to request much of the above information from the DHCP server. In particular, domain-name, domain-name-servers, and routers are configured via DHCP. These settings are typically necessary for proper network functionality, but are also usually static across machines at a given site. CM-7 Because the configuration information provided by the DHCP server could be maliciously provided to clients by a rogue DHCP server, the amount of information provided via DHCP should be minimized. Remove these definitions from the DHCP server configuration to ensure that legitimate clients do not unnecessarily rely on DHCP for this information. Configure Logging Ensure that the following line exists in /etc/rsyslog.conf:

daemon.*           /var/log/daemon.log

Configure logwatch or other log monitoring tools to summarize error conditions reported by the dhcpd process. By default, dhcpd logs notices to the daemon facility. Sending all daemon messages to a dedicated log file is part of the syslog configuration outlined in the Logging and Auditing section CCE-RHEL7-CCE-TBD Disable DHCP Client DHCP is the default network configuration method provided by the system installer, and common on many networks. Nevertheless, manual management of IP addresses for systems implies a greater degree of management and accountability for network activity. Disable DHCP Client For each interface on the system (e.g. eth0), edit /etc/sysconfig/network-scripts/ifcfg-interface and make the following changes:

    Correct the BOOTPROTO line to read:

    BOOTPROTO=none

    Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:

    NETMASK=255.255.255.0
    IPADDR=192.168.1.2
    GATEWAY=192.168.1.1

CM-7 366 Test attestation on 20121024 by DS DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances. CCE-RHEL7-CCE-TBD To verify that DHCP is not being used, examine the following file for each interface:

# /etc/sysconfig/network-scripts/ifcfg-interface

Look for the following:

BOOTPROTO=none

and the following, substituting the appropriate values based on your site's addressing scheme:

NETMASK=255.255.255.0
IPADDR=192.168.1.2
GATEWAY=192.168.1.1

Configure DHCP Client if Necessary If DHCP must be used, then certain configuration changes can minimize the amount of information it receives and applies from the network, and thus the amount of incorrect information a rogue DHCP server could successfully distribute. For more information on configuring dhclient, see the dhclient(8) and dhclient.conf(5) man pages. Minimize the DHCP-Configured Options Create the file /etc/dhcp/dhclient.conf, and add an appropriate setting for each of the ten configuration settings which can be obtained via DHCP. For each setting, do one of the following:
If the setting should not be configured remotely by the DHCP server, select an appropriate static value, and add the line:

supersede setting value;

If the setting should be configured remotely by the DHCP server, add the lines:

request setting;
require setting;

For example, suppose the DHCP server should provide only the IP address itself and the subnet mask. Then the entire file should look like:

supersede domain-name "example.com";
supersede domain-name-servers 192.168.1.2;
supersede nis-domain "";
supersede nis-servers "";
supersede ntp-servers "ntp.example.com ";
supersede routers 192.168.1.1;
supersede time-offset -18000;
request subnet-mask;
require subnet-mask;

In this example, the options nis-servers and nis-domain are set to empty strings, on the assumption that the deprecated NIS protocol is not in use. It is necessary to supersede settings for unused services so that they cannot be set by a hostile DHCP server. If an option is set to an empty string, dhclient will typically not attempt to configure the service. By default, the DHCP client program, dhclient, requests and applies ten configuration options (in addition to the IP address) from the DHCP server. subnet-mask, broadcast-address, time-offset, routers, domain-name, domain-name-servers, host-name, nis-domain, nis-servers, and ntp-servers. Many of the options requested and applied by dhclient may be the same for every system on a network. It is recommended that almost all configuration options be assigned statically, and only options which must vary on a host-by-host basis be assigned via DHCP. This limits the damage which can be done by a rogue DHCP server. If appropriate for your site, it is also possible to supersede the host-name directive in /etc/dhcp/dhclient.conf, establishing a static hostname for the machine. However, dhclient does not use the host name option provided by the DHCP server (instead using the value provided by a reverse DNS lookup). Network Time Protocol The Network Time Protocol is used to manage the system clock over a network. Computer clocks are not very accurate, so time will drift unpredictably on unmanaged systems. Central time protocols can be used both to ensure that time is consistent among a network of machines, and that their time is consistent with the outside world.

If every system on a network reliably reports the same time, then it is much easier to correlate log messages in case of an attack. In addition, a number of cryptographic protocols (such as Kerberos) use timestamps to prevent certain types of attacks. If your network does not have synchronized time, these protocols may be unreliable or even unusable.

Depending on the specifics of the network, global time accuracy may be just as important as local synchronization, or not very important at all. If your network is connected to the Internet, using a public timeserver (or one provided by your enterprise) provides globally accurate timestamps which may be essential in investigating or responding to an attack which originated outside of your network.

A typical network setup involves a small number of internal systems operating as NTP servers, and the remainder obtaining time information from those internal servers.

More information on how to configure the NTP server software, including configuration of cryptographic authentication for time data, is available at http://www.ntp.org. Enable the NTP Daemon The ntpd service can be enabled with the following command:

$ sudo systemctl enable ntpd

AU-8(1) 160 Test attestation on 20121024 by DS Enabling the ntpd service ensures that the ntpd service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches.

The NTP daemon offers all of the functionality of ntpdate, which is now deprecated. Additional information on this is available at http://support.ntp.org/bin/view/Dev/DeprecatingNtpdate CCE-RHEL7-CCE-TBD # # Enable ntpd.service for all systemd targets # systemctl enable ntpd.service # # Start ntpd.service if not currently running # systemctl start ntpd.service Run the following command to determine the current status of the ntpd service:

$ systemctl is-active ntpd

If the service is running, it should return the following:

active

Specify a Remote NTP Server To specify a remote NTP server for time synchronization, edit the file /etc/ntp.conf. Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver:

server ntpserver

This instructs the NTP software to contact that remote server to obtain time data. AU-8(1) 160 Test attestation on 20121024 by DS Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. CCE-RHEL7-CCE-TBD To verify that a remote NTP service is configured for time synchronization, open the following file:

/etc/ntp.conf

In the file, there should be a section similar to the following:

server ntpserver

Specify Additional Remote NTP Servers Additional NTP servers can be specified for time synchronization in the file /etc/ntp.conf. To do so, add additional lines of the following form, substituting the IP address or hostname of a remote NTP server for ntpserver:

server ntpserver

AU-8(1) Specifying additional NTP servers increases the availability of accurate time data, in the event that one of the specified servers becomes unavailable. This is typical for a system acting as an NTP server for other systems. CCE-RHEL7-CCE-TBD Mail Server Software Mail servers are used to send and receive email over the network. Mail is a very common service, and Mail Transfer Agents (MTAs) are obvious targets of network attack. Ensure that machines are not running MTAs unnecessarily, and configure needed MTAs as defensively as possible.

Very few systems at any site should be configured to directly receive email over the network. Users should instead use mail client programs to retrieve email from a central server that supports protocols such as IMAP or POP3. However, it is normal for most systems to be independently capable of sending email, for instance so that cron jobs can report output to an administrator. Most MTAs, including Postfix, support a submission-only mode in which mail can be sent from the local system to a central site MTA (or directly delivered to a local account), but the system still cannot receive mail directly over a network.

The alternatives program in RHEL permits selection of other mail server software (such as Sendmail), but Postfix is the default and is preferred. Postfix was coded with security in mind and can also be more effectively contained by SELinux as its modular design has resulted in separate processes performing specific actions. More information is available on its website, http://www.postfix.org. Enable Postfix Service The Postfix mail transfer agent is used for local mail delivery within the system. The default configuration only listens for connections to the default SMTP port (port 25) on the loopback interface (127.0.0.1). It is recommended to leave this service enabled for local mail delivery. The postfix service can be enabled with the following command:

$ sudo systemctl enable postfix

Test attestation on 20121024 by DS Local mail delivery is essential to some system maintenance and notification tasks. CCE-RHEL7-CCE-TBD # # Enable postfix.service for all systemd targets # systemctl enable postfix.service # # Start postfix.service if not currently running # systemctl start postfix.service Run the following command to determine the current status of the postfix service:

$ systemctl is-active postfix

If the service is running, it should return the following:

active

Uninstall Sendmail Package Sendmail is not the default mail transfer agent and is not installed by default. The sendmail package can be removed with the following command:

$ sudo yum erase sendmail

CM-7 Test attestation on 20121024 by DS The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead. CCE-RHEL7-CCE-TBD Run the following command to determine if the sendmail package is installed:

$ rpm -q sendmail

Configure SMTP For Mail Clients This section discusses settings for Postfix in a submission-only e-mail configuration. Disable Postfix Network Listening Edit the file /etc/postfix/main.cf to ensure that only the following inet_interfaces line appears:

inet_interfaces = localhost

CM-7 382 Test attestation on 20121024 by DS This ensures postfix accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack. CCE-RHEL7-CCE-TBD Run the following command to ensure postfix accepts mail messages from only the local system:

$ grep inet_interfaces /etc/postfix/main.cf

If properly configured, the output should show only localhost. Configure Operating System to Protect Mail Server The guidance in this section is appropriate for any host which is operating as a site MTA, whether the mail server runs using Sendmail, Postfix, or some other software. Configure SSL Certificates for Use with SMTP AUTH If SMTP AUTH is to be used, the use of SSL to protect credentials in transit is strongly recommended. There are also configurations for which it may be desirable to encrypt all mail in transit from one MTA to another, though such configurations are beyond the scope of this guide. In either event, the steps for creating and installing an SSL certificate are independent of the MTA in use, and are described here. Ensure Security of Postfix SSL Certificate Create the PKI directory for mail certificates, if it does not already exist:

$ sudo mkdir /etc/pki/tls/mail
$ sudo chown root:root /etc/pki/tls/mail
$ sudo chmod 755 /etc/pki/tls/mail

Using removable media or some other secure transmission format, install the files generated in the previous step onto the mail server:

/etc/pki/tls/mail/serverkey.pem: the private key mailserverkey.pem
/etc/pki/tls/mail/servercert.pem: the certificate file mailservercert.pem

Verify the ownership and permissions of these files:

$ sudo chown root:root /etc/pki/tls/mail/serverkey.pem
$ sudo chown root:root /etc/pki/tls/mail/servercert.pem
$ sudo chmod 600 /etc/pki/tls/mail/serverkey.pem
$ sudo chmod 644 /etc/pki/tls/mail/servercert.pem

Verify that the CA's public certificate file has been installed as /etc/pki/tls/CA/cacert.pem, and has the correct permissions:

$ sudo chown root:root /etc/pki/tls/CA/cacert.pem
$ sudo chmod 644 /etc/pki/tls/CA/cacert.pem

Configure Postfix if Necessary Postfix stores its configuration files in the directory /etc/postfix by default. The primary configuration file is /etc/postfix/main.cf. Configure SMTP Greeting Banner Edit /etc/postfix/main.cf, and add or correct the following line, substituting some other wording for the banner information if you prefer:

smtpd_banner = $myhostname ESMTP

AC-22 AU-13 The default greeting banner discloses that the listening mail process is Postfix. When remote mail senders connect to the MTA on port 25, they are greeted by an initial banner as part of the SMTP dialogue. This banner is necessary, but it frequently gives away too much information, including the MTA software which is in use, and sometimes also its version number. Remote mail senders do not need this information in order to send mail, so the banner should be changed to reveal only the hostname (which is already known and may be useful) and the word ESMTP, to indicate that the modern SMTP protocol variant is supported. CCE-RHEL7-CCE-TBD Configure Postfix Resource Usage to Limit Denial of Service Attacks Edit /etc/postfix/main.cf. Edit the following lines to configure the amount of system resources Postfix can consume:

default_process_limit = 100
smtpd_client_connection_count_limit = 10
smtpd_client_connection_rate_limit = 30
queue_minfree = 20971520
header_size_limit = 51200
message_size_limit = 10485760
smtpd_recipient_limit = 100

The values here are examples. Note: The values given here are examples, and may need to be modified for any particular site. By default, the Postfix anvil process gathers mail receipt statistics. To get information about about what connection rates are typical at your site, look in /var/log/maillog for lines with the daemon name postfix/anvil. These configuration options serve to make it more difficult for attackers to consume resources on the MTA host. The default_process_limit parameter controls how many smtpd processes can exist at a time, while smtpd_client_connection_count_limit controls the number of those which can be occupied by any one remote sender, and smtpd_client_connection_rate_limit controls the number of connections any one client can make per minute. By default, local hosts (those in mynetworks) are exempted from per-client rate limiting. The queue_minfree parameter establishes a free space threshold, in order to stop e-mail receipt before the queue filesystem is entirely full. The header_size_limit, message_size_limit, and smtpd_recipient_limit parameters place bounds on the legal sizes of messages received via SMTP. Control Mail Relaying Postfix's mail relay controls are implemented with the help of the smtpd recipient restrictions option, which controls the restrictions placed on the SMTP dialogue once the sender and recipient envelope addresses are known. The guidance in the following sections should be applied to all machines. If there are machines which must be allowed to relay mail, but which cannot be trusted to relay unconditionally, configure SMTP AUTH with SSL support. Configure Trusted Networks and Hosts Edit /etc/postfix/main.cf, and configure the contents of the mynetworks variable in one of the following ways:

    If any machine in the subnet containing the MTA may be trusted to relay messages, add or correct the following line:

    mynetworks_style = subnet

    This is also the default setting, and is in effect if all my_networks_style directives are commented.
    If only the MTA host itself is trusted to relay messages, add or correct the following line:

    mynetworks_style = host

    If the set of machines which can relay is more complicated, manually specify an entry for each netblock or IP address which is trusted to relay by setting the mynetworks variable directly:

    mynetworks = 10.0.0.0/16, 192.168.1.0/24, 127.0.0.1

The mynetworks variable must contain only the set of machines for which this MTA should unconditionally relay mail. This is a trust relationship - if spammers gain access to these machines, your site will effectively become an open relay. It is recommended that only machines which are managed by you or by another trusted organization be placed in mynetworks, and users of all other machines be required to use SMTP AUTH to send mail. Enact SMTP Relay Restrictions To configure Postfix to restrict addresses to which it will send mail, see: http://www.postfix.org/SMTPD_ACCESS_README.html#danger
The full contents of smtpd_recipient_restrictions will vary by site, since this is a common place to put spam restrictions and other site-specific options. The permit_mynetworks option allows all mail to be relayed from the machines in mynetworks. Then, the reject_unauth_destination option denies all mail whose destination address is not local, preventing any other machines from relaying. These two options should always appear in this order, and should usually follow one another immediately unless SMTP AUTH is used. Enact SMTP Recipient Restrictions To configure Postfix to restrict addresses to which it will send mail, see: http://www.postfix.org/SMTPD_ACCESS_README.html#danger
The full contents of smtpd_recipient_restrictions will vary by site, since this is a common place to put spam restrictions and other site-specific options. The permit_mynetworks option allows all mail to be relayed from the machines in mynetworks. Then, the reject_unauth_destination option denies all mail whose destination address is not local, preventing any other machines from relaying. These two options should always appear in this order, and should usually follow one another immediately unless SMTP AUTH is used. Require SMTP AUTH Before Relaying from Untrusted Clients SMTP authentication allows remote clients to relay mail safely by requiring them to authenticate before submitting mail. Postfix's SMTP AUTH uses an authentication library called SASL, which is not part of Postfix itself. To enable the use of SASL authentication, see http://www.postfix.org/SASL_README.html Use TLS for SMTP AUTH Postfix provides options to use TLS for certificate-based authentication and encrypted sessions. An encrypted session protects the information that is transmitted with SMTP mail or with SASL authentication. To configure Postfix to protect all SMTP AUTH transactions using TLS, see http://www.postfix.org/TLS_README.html. LDAP LDAP is a popular directory service, that is, a standardized way of looking up information from a central database. RHEL 7 includes software that enables a system to act as both an LDAP client and server. Configure OpenLDAP Clients This section provides information on which security settings are important to configure in OpenLDAP clients by manually editing the appropriate configuration files. RHEL 7 provides an automated configuration tool called authconfig and a graphical wrapper for authconfig called system-config-authentication. However, these tools do not provide as much control over configuration as manual editing of configuration files. The authconfig tools do not allow you to specify locations of SSL certificate files, which is useful when trying to use SSL cleanly across several protocols. Installation and configuration of OpenLDAP on RHEL 7 is available at https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/ch-Directory_Servers.html. Before configuring any system to be an LDAP client, ensure that a working LDAP server is present on the network. Configure LDAP Client to Use TLS For All Transactions Configure LDAP to enforce TLS use. First, edit the file /etc/pam_ldap.conf, and add or correct the following lines:

ssl start_tls

Then review the LDAP server and ensure TLS has been configured. CM-7 776 778 1453 Test attestation on 20121024 by DS The ssl directive specifies whether to use ssl or not. If not specified it will default to no. It should be set to start_tls rather than doing LDAP over SSL. CCE-RHEL7-CCE-TBD To ensure LDAP is configured to use TLS for all transactions, run the following command:

$ grep start_tls /etc/pam_ldap.conf

Configure Certificate Directives for LDAP Use of TLS Ensure a copy of a trusted CA certificate has been placed in the file /etc/pki/tls/CA/cacert.pem. Configure LDAP to enforce TLS use and to trust certificates signed by that CA. First, edit the file /etc/pam_ldap.conf, and add or correct either of the following lines:

tls_cacertdir /etc/pki/tls/CA

or

tls_cacertfile /etc/pki/tls/CA/cacert.pem

Then review the LDAP server and ensure TLS has been configured. CM-7 776 778 1453 Test attestation on 20121024 by DS The tls_cacertdir or tls_cacertfile directives are required when tls_checkpeer is configured (which is the default for openldap versions 2.1 and up). These directives define the path to the trust certificates signed by the site CA. CCE-RHEL7-CCE-TBD To ensure TLS is configured with trust certificates, run the following command:

$ grep cert /etc/pam_ldap.conf

Configure OpenLDAP Server This section details some security-relevant settings for an OpenLDAP server. Installation and configuration of OpenLDAP on RHEL 7 is available at: https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/ch-Directory_Servers.html. Uninstall openldap-servers Package The openldap-servers package should be removed if not in use. Is this machine the OpenLDAP server? If not, remove the package.

$ sudo yum erase openldap-servers

The openldap-servers RPM is not installed by default on RHEL 7 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed. CM-7 366 Test attestation on 20121024 by DS Unnecessary packages should not be installed to decrease the attack surface of the system. While this software is clearly essential on an LDAP server, it is not necessary on typical desktop or workstation systems. CCE-RHEL7-CCE-TBD To verify the openldap-servers package is not installed, run the following command:

$ rpm -q openldap-servers

The output should show the following:

package openldap-servers is not installed

Install and Protect LDAP Certificate Files Create the PKI directory for LDAP certificates if it does not already exist:

$ sudo mkdir /etc/pki/tls/ldap
$ sudo chown root:root /etc/pki/tls/ldap
$ sudo chmod 755 /etc/pki/tls/ldap

Using removable media or some other secure transmission format, install the certificate files onto the LDAP server:

    /etc/pki/tls/ldap/serverkey.pem: the private key ldapserverkey.pem
    /etc/pki/tls/ldap/servercert.pem: the certificate file ldapservercert.pem

Verify the ownership and permissions of these files:

$ sudo chown root:ldap /etc/pki/tls/ldap/serverkey.pem
$ sudo chown root:ldap /etc/pki/tls/ldap/servercert.pem
$ sudo chmod 640 /etc/pki/tls/ldap/serverkey.pem
$ sudo chmod 640 /etc/pki/tls/ldap/servercert.pem

Verify that the CA's public certificate file has been installed as /etc/pki/tls/CA/cacert.pem, and has the correct permissions:

$ sudo mkdir /etc/pki/tls/CA
$ sudo chown root:root /etc/pki/tls/CA/cacert.pem
$ sudo chmod 644 /etc/pki/tls/CA/cacert.pem

As a result of these steps, the LDAP server will have access to its own private certificate and the key with which that certificate is encrypted, and to the public certificate file belonging to the CA. Note that it would be possible for the key to be protected further, so that processes running as ldap could not read it. If this were done, the LDAP server process would need to be restarted manually whenever the server rebooted. NFS and RPC The Network File System is a popular distributed filesystem for the Unix environment, and is very widely deployed. This section discusses the circumstances under which it is possible to disable NFS and its dependencies, and then details steps which should be taken to secure NFS's configuration. This section is relevant to machines operating as NFS clients, as well as to those operating as NFS servers. Disable All NFS Services if Possible If there is not a reason for the system to operate as either an NFS client or an NFS server, follow all instructions in this section to disable subsystems required by NFS. The steps in this section will prevent a machine from operating as either an NFS client or an NFS server. Only perform these steps on machines which do not need NFS at all. Disable Services Used Only by NFS If NFS is not needed, disable the NFS client daemons nfslock, rpcgssd, and rpcidmapd.

All of these daemons run with elevated privileges, and many listen for network connections. If they are not needed, they should be disabled to improve system security posture. Disable Network File System Lock Service (nfslock) The Network File System Lock (nfslock) service starts the required remote procedure call (RPC) processes which allow clients to lock files on the server. If the local machine is not configured to mount NFS filesystems then this service should be disabled. The nfslock service can be disabled with the following command:

$ sudo systemctl disable nfslock

CCE-RHEL7-CCE-TBD # # Disable nfs-lock.service for all systemd targets # systemctl disable nfs-lock.service # # Stop nfs-lock.service if currently running # systemctl stop nfs-lock.service Disable Secure RPC Client Service (rpcgssd) The rpcgssd service manages RPCSEC GSS contexts required to secure protocols that use RPC (most often Kerberos and NFS). The rpcgssd service is the client-side of RPCSEC GSS. If the system does not require secure RPC then this service should be disabled. The rpcgssd service can be disabled with the following command:

$ sudo systemctl disable rpcgssd

CCE-RHEL7-CCE-TBD # # Disable nfs-secure.service (rpcgssd) for all systemd targets # systemctl disable nfs-secure.service # # Stop nfs-secure.service (rpcgssd) if currently running # systemctl stop nfs-secure.service Disable RPC ID Mapping Service (rpcidmapd) The rpcidmapd service is used to map user names and groups to UID and GID numbers on NFSv4 mounts. If NFS is not in use on the local system then this service should be disabled. The rpcidmapd service can be disabled with the following command:

$ sudo systemctl disable rpcidmapd

CCE-RHEL7-CCE-TBD # # Disable nfs-idmap.service (rpcidmapd) for all systemd targets # systemctl disable nfs-idmap.service # # Stop nfs-idmap.service (rpcidmapd) if currently running # systemctl stop nfs-idmap.service Disable netfs if Possible To determine if any network filesystems handled by netfs are currently mounted on the system execute the following command:

$ mount -t nfs,nfs4,smbfs,cifs,ncpfs

If the command did not return any output then disable netfs. Disable Network File Systems (netfs) The netfs script manages the boot-time mounting of several types of networked filesystems, of which NFS and Samba are the most common. If these filesystem types are not in use, the script can be disabled, protecting the system somewhat against accidental or malicious changes to /etc/fstab and against flaws in the netfs script itself. The netfs service can be disabled with the following command:

$ sudo systemctl disable netfs

CCE-RHEL7-CCE-TBD Configure All Machines which Use NFS The steps in this section are appropriate for all machines which run NFS, whether they operate as clients or as servers. Make Each Machine a Client or a Server, not Both If NFS must be used, it should be deployed in the simplest configuration possible to avoid maintainability problems which may lead to unnecessary security exposure. Due to the reliability and security problems caused by NFS (specially NFSv3 and NFSv2), it is not a good idea for machines which act as NFS servers to also mount filesystems via NFS. At the least, crossed mounts (the situation in which each of two servers mounts a filesystem from the other) should never be used. Configure NFS Services to Use Fixed Ports (NFSv3 and NFSv2) Firewalling should be done at each host and at the border firewalls to protect the NFS daemons from remote access, since NFS servers should never be accessible from outside the organization. However, by default for NFSv3 and NFSv2, the RPC Bind service assigns each NFS service to a port dynamically at service startup time. Dynamic ports cannot be protected by port filtering firewalls such as iptables.

Therefore, restrict each service to always use a given port, so that firewalling can be done effectively. Note that, because of the way RPC is implemented, it is not possible to disable the RPC Bind service even if ports are assigned statically to all RPC services.

In NFSv4, the mounting and locking protocols have been incorporated into the protocol, and the server listens on the the well-known TCP port 2049. As such, NFSv4 does not need to interact with the rpcbind, lockd, and rpc.statd daemons, which can and should be disabled in a pure NFSv4 environment. The rpc.mountd daemon is still required on the NFS server to setup exports, but is not involved in any over-the-wire operations. Configure lockd to use static TCP port Configure the lockd daemon to use a static TCP port as opposed to letting the RPC Bind service dynamically assign a port. Edit the file /etc/sysconfig/nfs. Add or correct the following line:

LOCKD_TCPPORT=lockd-port

Where lockd-port is a port which is not used by any other service on your network. Restrict service to always use a given port, so that firewalling can be done effectively. CCE-RHEL7-CCE-TBD Configure lockd to use static UDP port Configure the lockd daemon to use a static UDP port as opposed to letting the RPC Bind service dynamically assign a port. Edit the file /etc/sysconfig/nfs. Add or correct the following line:

LOCKD_UDPPORT=lockd-port

Where lockd-port is a port which is not used by any other service on your network. Restricting services to always use a given port enables firewalling to be done more effectively. CCE-RHEL7-CCE-TBD Configure statd to use static port Configure the statd daemon to use a static port as opposed to letting the RPC Bind service dynamically assign a port. Edit the file /etc/sysconfig/nfs. Add or correct the following line:

STATD_PORT=statd-port

Where statd-port is a port which is not used by any other service on your network. Restricting services to always use a given port enables firewalling to be done more effectively. CCE-RHEL7-CCE-TBD Configure mountd to use static port Configure the mountd daemon to use a static port as opposed to letting the RPC Bind service dynamically assign a port. Edit the file /etc/sysconfig/nfs. Add or correct the following line:

MOUNTD_PORT=statd-port

Where mountd-port is a port which is not used by any other service on your network. Restricting services to always use a given port enables firewalling to be done more effectively. CCE-RHEL7-CCE-TBD Configure NFS Clients The steps in this section are appropriate for machines which operate as NFS clients. Disable NFS Server Daemons There is no need to run the NFS server daemons nfs and rpcsvcgssd except on a small number of properly secured machines designated as NFS servers. Ensure that these daemons are turned off on clients. Specify UID and GID for Anonymous NFS Connections To specify the UID and GID for remote root users, edit the /etc/exports file and add the following for each export:


anonuid=value greater than UID_MAX from /etc/login.defs
anongid=value greater than GID_MAX from /etc/login.defs 

Alternatively, functionally equivalent values of 60001, 65534, 65535 may be used. Specifying the anonymous UID and GID ensures that the remote root user is mapped to a local account which has no permissions on the system. CCE-RHEL7-CCE-TBD Inspect the mounts configured in /etc/exports. Each mount should specify a value greater than UID_MAX and GID_MAX as defined in /etc/login.defs. Disable Network File System (nfs) The Network File System (NFS) service allows remote hosts to mount and interact with shared filesystems on the local machine. If the local machine is not designated as a NFS server then this service should be disabled. The nfs service can be disabled with the following command:

$ sudo systemctl disable nfs

Test attestation on 20121025 by DS Unnecessary services should be disabled to decrease the attack surface of the system. CCE-RHEL7-CCE-TBD # # Disable nfs.service for all systemd targets # systemctl disable nfs.service # # Stop nfs.service if currently running # systemctl stop nfs.service It is prudent to ensure the nfs service is disabled in system boot, as well as not currently running. First, run the following to verify the service is stopped:

$ service nfs status

If the service is stopped or disabled, it will return the following:

rpc.svcgssd is stopped
rpc.mountd is stopped
nfsd is stopped
rpc.rquotad is stopped

To verify that the nfs service is disabled, run the following command:

$ chkconfig --list nfs

If properly configured, the output should look like:

nfs            	0:off	1:off	2:off	3:off	4:off	5:off	6:off

Disable Secure RPC Server Service (rpcsvcgssd) The rpcsvcgssd service manages RPCSEC GSS contexts required to secure protocols that use RPC (most often Kerberos and NFS). The rpcsvcgssd service is the server-side of RPCSEC GSS. If the system does not require secure RPC then this service should be disabled. The rpcsvcgssd service can be disabled with the following command:

$ sudo systemctl disable rpcsvcgssd

Test attestation on 20121025 by DS Unnecessary services should be disabled to decrease the attack surface of the system. CCE-RHEL7-CCE-TBD # # Disable nfs-secure-server.service (rpcsvcgssd) for all systemd targets # systemctl disable nfs-secure-server.service # # Stop nfs-secure-server.service (rpcsvcgssd) if currently running # systemctl stop nfs-secure-server.service To check that the rpcsvcgssd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled rpcsvcgssd

Output should indicate the rpcsvcgssd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled rpcsvcgssd
disabled

Run the following command to verify rpcsvcgssd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active rpcsvcgssd

If the service is not running the command will return the following output:

inactive

Mount Remote Filesystems with Restrictive Options Edit the file /etc/fstab. For each filesystem whose type (column 3) is nfs or nfs4, add the text ,nodev,nosuid to the list of mount options in column 4. If appropriate, also add ,noexec.

See the section titled "Restrict Partition Mount Options" for a description of the effects of these options. In general, execution of files mounted via NFS should be considered risky because of the possibility that an adversary could intercept the request and substitute a malicious file. Allowing setuid files to be executed from remote servers is particularly risky, both for this reason and because it requires the clients to extend root-level trust to the NFS server. Mount Remote Filesystems with nodev Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of any NFS mounts. CM-7 MP-2 Test attestation on 20121025 by DS Legitimate device files should only exist in the /dev directory. NFS mounts should not present device files to users. CCE-RHEL7-CCE-TBD To verify the nodev option is configured for all NFS mounts, run the following command:

$ mount | grep nfs

All NFS mounts should show the nodev setting in parentheses. This is not applicable if NFS is not implemented. Mount Remote Filesystems with nosuid Add the nosuid option to the fourth column of /etc/fstab for the line which controls mounting of any NFS mounts. Test attestation on 20121025 by DS NFS mounts should not present suid binaries to users. Only vendor-supplied suid executables should be installed to their default location on the local filesystem. CCE-RHEL7-CCE-TBD To verify the nosuid option is configured for all NFS mounts, run the following command:

$ mount | grep nfs

All NFS mounts should show the nosuid setting in parentheses. This is not applicable if NFS is not implemented. Configure NFS Servers The steps in this section are appropriate for machines which operate as NFS servers. Configure the Exports File Restrictively Linux's NFS implementation uses the file /etc/exports to control what filesystems and directories may be accessed via NFS. (See the exports(5) manpage for more information about the format of this file.)

The syntax of the exports file is not necessarily checked fully on reload, and syntax errors can leave your NFS configuration more open than intended. Therefore, exercise caution when modifying the file.

The syntax of each line in /etc/exports is:

/DIR	host1(opt1,opt2) host2(opt3)

where /DIR is a directory or filesystem to export, hostN is an IP address, netblock, hostname, domain, or netgroup to which to export, and optN is an option. Use Access Lists to Enforce Authorization Restrictions When configuring NFS exports, ensure that each export line in /etc/exports contains a list of hosts which are allowed to access that export. If no hosts are specified on an export line, then that export is available to any remote host which requests it. All lines of the exports file should specify the hosts (or subnets, if needed) which are allowed to access the exported directory, so that unknown or remote hosts will be denied.

Authorized hosts can be specified in several different formats:

    Name or alias that is recognized by the resolver
    Fully qualified domain name
    IP address
    IP subnets in the format address/netmask or address/CIDR

Export Filesystems Read-Only if Possible If a filesystem is being exported so that users can view the files in a convenient fashion, but there is no need for users to edit those files, exporting the filesystem read-only removes an attack vector against the server. The default filesystem export mode is ro, so do not specify rw without a good reason. Use Root-Squashing on All Exports If a filesystem is exported using root squashing, requests from root on the client are considered to be unprivileged (mapped to a user such as nobody). This provides some mild protection against remote abuse of an NFS server. Root squashing is enabled by default, and should not be disabled.

Ensure that no line in /etc/exports contains the option no_root_squash. If the NFS server allows root access to local file systems from remote hosts, this access could be used to compromise the system. CCE-RHEL7-CCE-TBD Restrict NFS Clients to Privileged Ports By default, the server NFS implementation requires that all client requests be made from ports less than 1024. If your organization has control over machines connected to its network, and if NFS requests are prohibited at the border firewall, this offers some protection against malicious requests from unprivileged users. Therefore, the default should not be changed.

To ensure that the default has not been changed, ensure no line in /etc/exports contains the option insecure. Allowing client requests to be made from ports higher than 1024 could allow a unprivileged user to initiate an NFS connection. If the unprivileged user account has been compromised, an attacker could gain access to data on the NFS server. CCE-RHEL7-CCE-TBD Ensure Insecure File Locking is Not Allowed By default the NFS server requires secure file-lock requests, which require credentials from the client in order to lock a file. Most NFS clients send credentials with file lock requests, however, there are a few clients that do not send credentials when requesting a file-lock, allowing the client to only be able to lock world-readable files. To get around this, the insecure_locks option can be used so these clients can access the desired export. This poses a security risk by potentially allowing the client access to data for which it does not have authorization. Remove any instances of the insecure_locks option from the file /etc/exports. 764 Allowing insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user. CCE-RHEL7-CCE-TBD To verify insecure file locking has been disabled, run the following command:

$ grep insecure_locks /etc/exports

DNS Server Most organizations have an operational need to run at least one nameserver. However, there are many common attacks involving DNS server software, and this server software should be disabled on any system on which it is not needed. Disable DNS Server DNS software should be disabled on any machine which does not need to be a nameserver. Note that the BIND DNS server software is not installed on RHEL 7 by default. The remainder of this section discusses secure configuration of machines which must be nameservers. Disable DNS Server The named service can be disabled with the following command:

$ sudo systemctl disable named

CM-7 366 All network services involve some risk of compromise due to implementation flaws and should be disabled if possible. CCE-RHEL7-CCE-TBD To check that the named service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled named

Output should indicate the named service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled named
disabled

Run the following command to verify named is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active named

If the service is not running the command will return the following output:

inactive

Uninstall bind Package To remove the bind package, which contains the named service, run the following command:

$ sudo yum erase bind

CM-7 366 If there is no need to make DNS server software available, removing it provides a safeguard against its activation. CCE-RHEL7-CCE-TBD Run the following command to determine if the bind package is installed:

$ rpm -q bind

Isolate DNS from Other Services This section discusses mechanisms for preventing the DNS server from interfering with other services. This is done both to protect the remainder of the network should a nameserver be compromised, and to make direct attacks on nameservers more difficult. Run DNS Software on Dedicated Servers Since DNS is a high-risk service which must frequently be made available to the entire Internet, it is strongly recommended that no other services be offered by machines which act as organizational DNS servers. Run DNS Software in a chroot Jail Install the bind-chroot package:

$ sudo yum install bind-chroot

Place a valid named.conf file inside the chroot jail:

$ sudo cp /etc/named.conf /var/named/chroot/etc/named.conf
$ sudo chown root:root /var/named/chroot/etc/named.conf
$ sudo chmod 644 /var/named/chroot/etc/named.conf

Create and populate an appropriate zone directory within the jail, based on the options directive. If your named.conf includes:

options {
directory "/path/to/DIRNAME ";
...
}

then copy that directory and its contents from the original zone directory:

$ sudo cp -r /path/to/DIRNAME /var/named/chroot/DIRNAME

Add or correct the following line within /etc/sysconfig/named:

ROOTDIR=/var/named/chroot

If you are running BIND in a chroot jail, then you should use the jailed named.conf as the primary nameserver configuration file. That is, when this guide recommends editing /etc/named.conf, you should instead edit /var/named/chroot/etc/named.conf. Chroot jails are not foolproof. However, they serve to make it more difficult for a compromised program to be used to attack the entire host. They do this by restricting a program's ability to traverse the directory upward, so that files outside the jail are not visible to the chrooted process. Since RHEL supports a standard mechanism for placing BIND in a chroot jail, you should take advantage of this feature. Protect DNS Data from Tampering or Attack This section discusses DNS configuration options which make it more difficult for attackers to gain access to private DNS data or to modify DNS data. Run Separate DNS Servers for External and Internal Queries Is it possible to run external and internal nameservers on separate machines? If so, follow the configuration guidance in this section. On the external nameserver, edit /etc/named.conf to add or correct the following directives:

options {
  allow-query { any; };
  recursion no;
  ...
};
zone "example.com " IN {
  ...
};

On the internal nameserver, edit /etc/named.conf. Add or correct the following directives, where SUBNET is the numerical IP representation of your organization in the form xxx.xxx.xxx.xxx/xx:

acl internal {
  SUBNET ;
  localhost;
};
options {
  allow-query { internal; };
  ...
};
zone "internal.example.com " IN {
  ...
};

Enterprise nameservers generally serve two functions. One is to provide public information about the machines in a domain for the benefit of outside users who wish to contact those machines, for instance in order to send mail to users in the enterprise, or to visit the enterprise's external web page. The other is to provide nameservice to client machines within the enterprise. Client machines require both private information about enterprise machines (which may be different from the public information served to the rest of the world) and public information about machines outside the enterprise, which is used to send mail or visit websites outside of the organization.
In order to provide the public nameservice function, it is necessary to share data with untrusted machines which request it - otherwise, the enterprise cannot be conveniently contacted by outside users. However, internal data should be protected from disclosure, and serving irrelevant public name queries for outside domains leaves the DNS server open to cache poisoning and other attacks. Therefore, local network nameservice functions should not be provided to untrusted machines.
Separate machines should be used to fill these two functions whenever possible. Use Views to Partition External and Internal Information If it is not possible to run external and internal nameservers on separate physical machines, run BIND9 and simulate this feature using views. Edit /etc/named.conf. Add or correct the following directives (where SUBNET is the numerical IP representation of your organization in the form xxx.xxx.xxx.xxx/xx):

acl internal {
  SUBNET ;
  localhost;
};
view "internal-view" {
  match-clients { internal; };
  zone "." IN {
    type hint;
    file "db.cache";
  };
  zone "internal.example.com " IN {
    ...
  };
};

view "external-view" {
  match-clients { any; };
  recursion no;
  zone "example.com " IN {
    ...
  };
};

As shown in the example, database files which are required for recursion, such as the root hints file, must be available to any clients which are allowed to make recursive queries. Under typical circumstances, this includes only the internal clients which are allowed to use this server as a general-purpose nameserver. The view feature is provided by BIND9 as a way to allow a single nameserver to make different sets of data available to different sets of clients. If possible, it is always better to run external and internal nameservers on separate machines, so that even complete compromise of the external server cannot be used to obtain internal data or confuse internal DNS clients. However, this is not always feasible, and use of a feature like views is preferable to leaving internal DNS data entirely unprotected. Disable Zone Transfers from the Nameserver Is it necessary for a secondary nameserver to receive zone data via zone transfer from the primary server? If not, follow the instructions in this section. If so, see the next section for instructions on protecting zone transfers. Add or correct the following directive within /etc/named.conf:

options {
  allow-transfer { none; };
  ...
}

If both the primary and secondary nameserver are under your control, or if you have only one nameserver, it may be possible to use an external configuration management mechanism to distribute zone updates. In that case, it is not necessary to allow zone transfers within BIND itself, so they should be disabled to avoid the potential for abuse. CCE-RHEL7-CCE-TBD Authenticate Zone Transfers If it is necessary for a secondary nameserver to receive zone data via zone transfer from the primary server, follow the instructions here. Use dnssec-keygen to create a symmetric key file in the current directory:

$ cd /tmp
$ sudo dnssec-keygen -a HMAC-MD5 -b 128 -n HOST dns.example.com
Kdns.example.com .+aaa +iiiii

This output is the name of a file containing the new key. Read the file to find the base64-encoded key string:

$ sudo cat Kdns.example.com .+NNN +MMMMM .key
dns.example.com IN KEY 512 3 157 base64-key-string

Add the directives to /etc/named.conf on the primary server:

key zone-transfer-key {
  algorithm hmac-md5;
  secret "base64-key-string ";
};
zone "example.com " IN {
  type master;
  allow-transfer { key zone-transfer-key; };
  ...
};

Add the directives below to /etc/named.conf on the secondary nameserver:

key zone-transfer-key {
  algorithm hmac-md5;
  secret "base64-key-string ";
};

server IP-OF-MASTER {
  keys { zone-transfer-key; };
};

zone "example.com " IN {
  type slave;
  masters { IP-OF-MASTER ; };
  ...
};

The purpose of the dnssec-keygen command is to create the shared secret string base64-key-string. Once this secret has been obtained and inserted into named.conf on the primary and secondary servers, the key files Kdns.example.com .+NNN +MMMMM .key and Kdns.example.com .+NNN +MMMMM .private are no longer needed, and may safely be deleted. CM-7 The BIND transaction signature (TSIG) functionality allows primary and secondary nameservers to use a shared secret to verify authorization to perform zone transfers. This method is more secure than using IP-based limiting to restrict nameserver access, since IP addresses can be easily spoofed. However, if you cannot configure TSIG between your servers because, for instance, the secondary nameserver is not under your control and its administrators are unwilling to configure TSIG, you can configure an allow-transfer directive with numerical IP addresses or ACLs as a last resort. CCE-RHEL7-CCE-TBD Disable Dynamic Updates Is there a mission-critical reason to enable the risky dynamic update functionality? If not, edit /etc/named.conf. For each zone specification, correct the following directive if necessary:

zone "example.com " IN {
  allow-update { none; };
  ...
};

Dynamic updates allow remote servers to add, delete, or modify any entries in your zone file. Therefore, they should be considered highly risky, and disabled unless there is a very good reason for their use. If dynamic updates must be allowed, IP-based ACLs are insufficient protection, since they are easily spoofed. Instead, use TSIG keys (see the previous section for an example), and consider using the update-policy directive to restrict changes to only the precise type of change needed. CCE-RHEL7-CCE-TBD FTP Server FTP is a common method for allowing remote access to files. Like telnet, the FTP protocol is unencrypted, which means that passwords and other data transmitted during the session can be captured and that the session is vulnerable to hijacking. Therefore, running the FTP server software is not recommended.

However, there are some FTP server configurations which may be appropriate for some environments, particularly those which allow only read-only anonymous access as a means of downloading data available to the public. Disable vsftpd if Possible Disable vsftpd Service The vsftpd service can be disabled with the following command:

$ sudo systemctl disable vsftpd

CM-7 1436 Running FTP server software provides a network-based avenue of attack, and should be disabled if not needed. Furthermore, the FTP protocol is unencrypted and creates a risk of compromising sensitive information. CCE-RHEL7-CCE-TBD if service vsftpd status >/dev/null; then service vsftpd stop fi To check that the vsftpd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled vsftpd

Output should indicate the vsftpd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled vsftpd
disabled

Run the following command to verify vsftpd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active vsftpd

If the service is not running the command will return the following output:

inactive

Uninstall vsftpd Package The vsftpd package can be removed with the following command:

$ sudo yum erase vsftpd

CM-7 1436 Removing the vsftpd package decreases the risk of its accidental activation. CCE-RHEL7-CCE-TBD Run the following command to determine if the vsftpd package is installed:

$ rpm -q vsftpd

Use vsftpd to Provide FTP Service if Necessary Install vsftpd Package If this machine must operate as an FTP server, install the vsftpd package via the standard channels.

$ sudo yum install vsftpd

CM-7 After RHEL 2.1, Red Hat switched from distributing wu-ftpd with RHEL to distributing vsftpd. For security and for consistency with future Red Hat releases, the use of vsftpd is recommended. CCE-RHEL7-CCE-TBD yum -y install vsftpd Use vsftpd to Provide FTP Service if Necessary The primary vsftpd configuration file is /etc/vsftpd.conf, if that file exists, or /etc/vsftpd/vsftpd.conf if it does not. Enable Logging of All FTP Transactions Add or correct the following configuration options within the vsftpd configuration file, located at /etc/vsftpd/vsftpd.conf:

xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES

If verbose logging to vsftpd.log is done, sparse logging of downloads to /var/log/xferlog will not also occur. However, the information about what files were downloaded is included in the information logged to vsftpd.log To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the FTP server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log. CCE-RHEL7-CCE-TBD Find if logging is applied to the FTP daemon.

Procedures:

If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file:

$ grep vsftpd /etc/xinetd.d/*

$ grep server_args vsftpd xinetd.d startup file

This will indicate the vsftpd config file used when starting through xinetd. If the server_args line is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) is used.

$ sudo grep xferlog_enable vsftpd config file

Create Warning Banners for All FTP Users Edit the vsftpd configuration file, which resides at /etc/vsftpd/vsftpd.conf by default. Add or correct the following configuration options:

banner_file=/etc/issue

48 This setting will cause the system greeting banner to be used for FTP connections as well. CCE-RHEL7-CCE-TBD If FTP services are not installed, this is not applicable.

To verify this configuration, run the following command:

grep "banner_file" /etc/vsftpd/vsftpd.conf

The output should show the value of banner_file is set to /etc/issue, an example of which is shown below:

$ sudo grep "banner_file" /etc/vsftpd/vsftpd.conf
banner_file=/etc/issue

Restrict the Set of Users Allowed to Access FTP This section describes how to disable non-anonymous (password-based) FTP logins, or, if it is not possible to do this entirely due to legacy applications, how to restrict insecure FTP login to only those users who have an identified need for this access. Restrict Access to Anonymous Users if Possible Is there a mission-critical reason for users to transfer files to/from their own accounts using FTP, rather than using a secure protocol like SCP/SFTP? If not, edit the vsftpd configuration file. Add or correct the following configuration option:

local_enable=NO

If non-anonymous FTP logins are necessary, follow the guidance in the remainder of this section to secure these logins as much as possible. CM-7 AC-3 The use of non-anonymous FTP logins is strongly discouraged. Since SSH clients and servers are widely available, and since SSH provides support for a transfer mode which resembles FTP in user interface, there is no good reason to allow password-based FTP access. CCE-RHEL7-CCE-TBD Limit Users Allowed FTP Access if Necessary If there is a mission-critical reason for users to access their accounts via the insecure FTP protocol, limit the set of users who are allowed this access. Edit the vsftpd configuration file. Add or correct the following configuration options:

userlist_enable=YES
userlist_file=/etc/vsftp.ftpusers
userlist_deny=NO

Edit the file /etc/vsftp.ftpusers. For each user USERNAME who should be allowed to access the system via FTP, add a line containing that user's name:

USERNAME

If anonymous access is also required, add the anonymous usernames to /etc/vsftp.ftpusers as well.

anonymous
ftp

Historically, the file /etc/ftpusers contained a list of users who were not allowed to access the system via FTP. It was used to prevent system users such as the root user from logging in via the insecure FTP protocol. However, when the configuration option userlist deny=NO is set, vsftpd interprets ftpusers as the set of users who are allowed to login via FTP. Since it should be possible for most users to access their accounts via secure protocols, it is recommended that this setting be used, so that non-anonymous FTP access can be limited to legacy users who have been explicitly identified. Disable FTP Uploads if Possible Is there a mission-critical reason for users to upload files via FTP? If not, edit the vsftpd configuration file to add or correct the following configuration options:

write_enable=NO

If FTP uploads are necessary, follow the guidance in the remainder of this section to secure these transactions as much as possible. Anonymous FTP can be a convenient way to make files available for universal download. However, it is less common to have a need to allow unauthenticated users to place files on the FTP server. If this must be done, it is necessary to ensure that files cannot be uploaded and downloaded from the same directory. CCE-RHEL7-CCE-TBD Place the FTP Home Directory on its Own Partition By default, the anonymous FTP root is the home directory of the FTP user account. The df command can be used to verify that this directory is on its own partition. If there is a mission-critical reason for anonymous users to upload files, precautions must be taken to prevent these users from filling a disk used by other services. CCE-RHEL7-CCE-TBD Configure Firewalls to Protect the FTP Server By default, iptables blocks access to the ports used by the web server. To configure iptables to allow port 21 traffic one must edit /etc/sysconfig/iptables and /etc/sysconfig/ip6tables (if IPv6 is in use). Add the following line, ensuring that it appears before the final LOG and DROP lines for the INPUT chain:

-A INPUT -m state --state NEW -p tcp --dport 21 -j ACCEPT

Edit the file /etc/sysconfig/iptables-config. Ensure that the space-separated list of modules contains the FTP connection tracking module:

IPTABLES_MODULES="ip_conntrack_ftp"

These settings configure iptables to allow connections to an FTP server. The first line allows initial connections to the FTP server port. FTP is an older protocol which is not very compatible with firewalls. During the initial FTP dialogue, the client and server negotiate an arbitrary port to be used for data transfer. The ip_conntrack_ftp module is used by iptables to listen to that dialogue and allow connections to the data ports which FTP negotiates. This allows an FTP server to operate on a machine which is running a firewall. Web Server The web server is responsible for providing access to content via the HTTP protocol. Web servers represent a significant security risk because:

    The HTTP port is commonly probed by malicious sources
    Web server software is very complex, and includes a long history of vulnerabilities
    The HTTP protocol is unencrypted and vulnerable to passive monitoring



The system's default web server software is Apache 2 and is provided in the RPM package httpd. Disable Apache if Possible If Apache was installed and activated, but the system does not need to act as a web server, then it should be disabled and removed from the system. Disable httpd Service The httpd service can be disabled with the following command:

$ sudo systemctl disable httpd

CM-7 Running web server software provides a network-based avenue of attack, and should be disabled if not needed. CCE-RHEL7-CCE-TBD To check that the httpd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled httpd

Output should indicate the httpd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled httpd
disabled

Run the following command to verify httpd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active httpd

If the service is not running the command will return the following output:

inactive

Uninstall httpd Package The httpd package can be removed with the following command:

$ sudo yum erase httpd

CM-7 If there is no need to make the web server software available, removing it provides a safeguard against its activation. CCE-RHEL7-CCE-TBD if rpm -qa | grep -q httpd; then yum -y remove httpd fi Run the following command to determine if the httpd package is installed:

$ rpm -q httpd

Install Apache if Necessary If httpd was not installed and activated, but the system needs to act as a web server, then it should be installed on the system. Follow these guidelines to install it defensively. The httpd package can be installed with the following command:

$ sudo yum install httpd

This method of installation is recommended over installing the "Web Server" package group during the system installation process. The Web Server package group includes many packages which are likely extraneous, while the command-line method installs only the required httpd package itself. Confirm Minimal Built-in Modules Installed The default httpd installation minimizes the number of modules that are compiled directly into the binary (core prefork http_core mod_so). This minimizes risk by limiting the capabilities allowed by the web server. Query the set of compiled-in modules using the following command:

$ httpd -l

If the number of compiled-in modules is significantly larger than the aforementioned set, this guide recommends re-installing httpd with a reduced configuration. Minimizing the number of modules that are compiled into the httpd binary, reduces risk by limiting the capabilities allowed by the webserver. Secure Apache Configuration The httpd configuration file is /etc/httpd/conf/httpd.conf. Apply the recommendations in the remainder of this section to this file. Restrict Web Server Information Leakage The ServerTokens and ServerSignature directives determine how much information the web server discloses about the configuration of the system. Set httpd ServerTokens Directive to Prod ServerTokens Prod restricts information in page headers, returning only the word "Apache."

Add or correct the following directive in /etc/httpd/conf/httpd.conf:

ServerTokens Prod

CM-7 Information disclosed to clients about the configuration of the web server and system could be used to plan an attack on the given system. This information disclosure should be restricted to a minimum. CCE-RHEL7-CCE-TBD Set httpd ServerSignature Directive to Off ServerSignature Off restricts httpd from displaying server version number on error pages.

Add or correct the following directive in /etc/httpd/conf/httpd.conf:

ServerSignature Off

CM-7 Information disclosed to clients about the configuration of the web server and system could be used to plan an attack on the given system. This information disclosure should be restricted to a minimum. CCE-RHEL7-CCE-TBD Minimize Web Server Loadable Modules A default installation of httpd includes a plethora of dynamically shared objects (DSO) that are loaded at run-time. Unlike the aforementioned compiled-in modules, a DSO can be disabled in the configuration file by removing the corresponding LoadModule directive.

Note: A DSO only provides additional functionality if associated directives are included in the httpd configuration file. It should also be noted that removing a DSO will produce errors on httpd startup if the configuration file contains directives that apply to that module. Refer to http://httpd.apache.org/docs/ for details on which directives are associated with each DSO.

Following each DSO removal, the configuration can be tested with the following command to check if everything still works:

$ sudo service httpd configtest

The purpose of each of the modules loaded by default will now be addressed one at a time. If none of a module's directives are being used, remove it. httpd Core Modules These modules comprise a basic subset of modules that are likely needed for base httpd functionality; ensure they are not commented out in /etc/httpd/conf/httpd.conf:

LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule authn_default_module modules/mod_authn_default.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule authz_groupfile_module modules/mod_authz_groupfile.so
LoadModule authz_default_module modules/mod_authz_default.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule logio_module modules/mod_logio.so
LoadModule setenvif_module modules/mod_setenvif.so
LoadModule mime_module modules/mod_mome.so
LoadModule autoindex_module modules/mod_autoindex.so
LoadModule negotiation_module modules/mod_negotiation.so
LoadModule dir_module modules/mod_dir.so
LoadModule alias_module modules/mod_alias.so

Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. Minimize Modules for HTTP Basic Authentication The following modules are necessary if this web server will provide content that will be restricted by a password.

Authentication can be performed using local plain text password files (authn_file), local DBM password files (authn_dbm) or an LDAP directory. The only module required by the web server depends on your choice of authentication. Comment out the modules you don't need from the following:

LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authn_dbm_module modules/mod_authn_dbm.so

authn_alias allows for authentication based on aliases. authn_anon allows anonymous authentication similar to that of anonymous ftp sites. authz_owner allows authorization based on file ownership. authz_dbm allows for authorization based on group membership if the web server is using DBM authentication.

If the above functionality is unnecessary, comment out the related module:

#LoadModule authn_alias_module modules/mod_authn_alias.so
#LoadModule authn_anon_module modules/mod_authn_anon.so
#LoadModule authz_owner_module modules/mod_authz_owner.so
#LoadModule authz_dbm_module modules/mod_authz_dbm.so

Disable HTTP Digest Authentication The auth_digest module provides encrypted authentication sessions. If this functionality is unnecessary, comment out the related module:

#LoadModule auth_digest_module modules/mod_auth_digest.so

Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable HTTP mod_rewrite The mod_rewrite module is very powerful and can protect against certain classes of web attacks. However, it is also very complex and has a significant history of vulnerabilities itself. If its functionality is unnecessary, comment out the related module:

#LoadModule rewrite_module modules/mod_rewrite.so

Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable LDAP Support The ldap module provides HTTP authentication via an LDAP directory. If its functionality is unnecessary, comment out the related modules:

#LoadModule ldap_module modules/mod_ldap.so
#LoadModule authnz_ldap_module modules/mod_authnz_ldap.so

If LDAP is to be used, SSL encryption should be used as well. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable Server Side Includes Server Side Includes provide a method of dynamically generating web pages through the insertion of server-side code. However, the technology is also deprecated and introduces significant security concerns. If this functionality is unnecessary, comment out the related module:

#LoadModule include_module modules/mod_include.so

If there is a critical need for Server Side Includes, they should be enabled with the option IncludesNoExec to prevent arbitrary code execution. Additionally, user supplied data should be encoded to prevent cross-site scripting vulnerabilities. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable MIME Magic The mime_magic module provides a second layer of MIME support that in most configurations is likely extraneous. If its functionality is unnecessary, comment out the related module:

#LoadModule mime_magic_module modules/mod_mime_magic.so

Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable WebDAV (Distributed Authoring and Versioning) WebDAV is an extension of the HTTP protocol that provides distributed and collaborative access to web content. If its functionality is unnecessary, comment out the related modules:

#LoadModule dav_module modules/mod_dav.so
#LoadModule dav_fs_module modules/mod_dav_fs.so

If there is a critical need for WebDAV, extra care should be taken in its configuration. Since DAV access allows remote clients to manipulate server files, any location on the server that is DAV enabled should be protected by access controls. Minimizing the number of loadable modules available to the web server, reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable Server Activity Status The status module provides real-time access to statistics on the internal operation of the web server. This may constitute an unnecessary information leak and should be disabled unless necessary. To do so, comment out the related module:

#LoadModule status_module modules/mod_status.so

If there is a critical need for this module, ensure that access to the status page is properly restricted to a limited set of hosts in the status handler configuration. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable Web Server Configuration Display The info module creates a web page illustrating the configuration of the web server. This can create an unnecessary security leak and should be disabled. If its functionality is unnecessary, comment out the module:

#LoadModule info_module modules/mod_info.so

If there is a critical need for this module, use the Location directive to provide an access control list to restrict access to the information. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable URL Correction on Misspelled Entries The speling module attempts to find a document match by allowing one misspelling in an otherwise failed request. If this functionality is unnecessary, comment out the module:

#LoadModule speling_module modules/mod_speling.so

This functionality weakens server security by making site enumeration easier. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable Proxy Support The proxy module provides proxying support, allowing httpd to forward requests and serve as a gateway for other servers. If its functionality is unnecessary, comment out the module:

#LoadModule proxy_module modules/mod_proxy.so

If proxy support is needed, load mod_proxy and the appropriate proxy protocol handler module (one of mod_proxy_http, mod_proxy_ftp, or mod_proxy_connect). Additionally, make certain that a server is secure before enabling proxying, as open proxy servers are a security risk. mod_proxy_balancer enables load balancing, but requires that mod status be enabled. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable Cache Support The cache module allows httpd to cache data, optimizing access to frequently accessed content. However, it introduces potential security flaws such as the possibility of circumventing Allow and Deny directives.

If this functionality is unnecessary, comment out the module:

#LoadModule cache_module modules/mod_cache.so

If caching is required, it should not be enabled for any limited-access content. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Disable CGI Support The cgi module allows HTML to interact with the CGI web programming language.

If this functionality is unnecessary, comment out the module:

#LoadModule cgi_module modules/mod_cgi.so

If the web server requires the use of CGI, enable mod_cgi. Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Minimize Various Optional Components The following modules perform very specific tasks, sometimes providing access to just a few additional directives. If such functionality is not required (or if you are not using these directives), comment out the associated module:

    External filtering (response passed through external program prior to client delivery)

    #LoadModule ext_filter_module modules/mod_ext_filter.so

    User-specified Cache Control and Expiration

    #LoadModule expires_module modules/mod_expires.so

    Compression Output Filter (provides content compression prior to client delivery)

    #LoadModule deflate_module modules/mod_deflate.so

    HTTP Response/Request Header Customization

    #LoadModule headers_module modules/mod_headers.so

    User activity monitoring via cookies

    #LoadModule usertrack_module modules/mod_usertrack.so

    Dynamically configured mass virtual hosting

    #LoadModule vhost_alias_module modules/mod_vhost_alias.so

Minimizing the number of loadable modules available to the web server reduces risk by limiting the capabilities allowed by the web server. Minimize Configuration Files Included The Include directive directs httpd to load supplementary configuration files from a provided path. The default configuration loads all files that end in .conf from the /etc/httpd/conf.d directory.

To restrict excess configuration, the following line should be commented out and replaced with Include directives that only reference required configuration files:

#Include conf.d/*.conf

If the above change was made, ensure that the SSL encryption remains loaded by explicitly including the corresponding configuration file:

Include conf.d/ssl.conf

If PHP is necessary, a similar alteration must be made:

Include conf.d/php.conf

Explicitly listing the configuration files to be loaded during web server start-up avoids the possibility of unwanted or malicious configuration files to be automatically included as part of the server's running configuration. Directory Restrictions The Directory tags in the web server configuration file allow finer grained access control for a specified directory. All web directories should be configured on a case-by-case basis, allowing access only where needed. Restrict Root Directory The httpd root directory should always have the most restrictive configuration enabled.

<Directory / >
   Options None
   AllowOverride None
   Order allow,deny
</Directory>

The Web Server's root directory content should be protected from unauthorized access by web clients. CCE-RHEL7-CCE-TBD Restrict Web Directory The default configuration for the web (/var/www/html) Directory allows directory indexing (Indexes) and the following of symbolic links (FollowSymLinks). Neither of these is recommended.

The /var/www/html directory hierarchy should not be viewable via the web, and symlinks should only be followed if the owner of the symlink also owns the linked file.

Ensure that this policy is adhered to by altering the related section of the configuration:

<Directory "/var/www/html">
#  ...
   Options SymLinksIfOwnerMatch
#  ...
</Directory>

Access to the web server's directory hierarchy could allow access to unauthorized files by web clients. Following symbolic links could also allow such access. CCE-RHEL7-CCE-TBD Restrict Other Critical Directories All accessible web directories should be configured with similarly restrictive settings. The Options directive should be limited to necessary functionality and the AllowOverride directive should be used only if needed. The Order and Deny access control tags should be used to deny access by default, allowing access only where necessary. Directories accessible from a web client should be configured with the least amount of access possible in order to avoid unauthorized access to restricted content or server information. CCE-RHEL7-CCE-TBD Limit Available Methods Web server methods are defined in section 9 of RFC 2616 (http://www.ietf.org/rfc/rfc2616.txt). If a web server does not require the implementation of all available methods, they should be disabled.

Note: GET and POST are the most common methods. A majority of the others are limited to the WebDAV protocol.

<Directory /var/www/html>
# ...
   # Only allow specific methods (this command is case-sensitive!)
   <LimitExcept GET POST>
      Order allow,deny
   </LimitExcept>
# ...
</Directory>

Minimizing the number of available methods to the web client reduces risk by limiting the capabilities allowed by the web server. CCE-RHEL7-CCE-TBD Use Appropriate Modules to Improve httpd's Security Among the modules available for httpd are several whose use may improve the security of the web server installation. This section recommends and discusses the deployment of security-relevant modules. Deploy mod_ssl Because HTTP is a plain text protocol, all traffic is susceptible to passive monitoring. If there is a need for confidentiality, SSL should be configured and enabled to encrypt content.

Note: mod_nss is a FIPS 140-2 certified alternative to mod_ssl. The modules share a considerable amount of code and should be nearly identical in functionality. If FIPS 140-2 validation is required, then mod_nss should be used. If it provides some feature or its greater compatibility is required, then mod_ssl should be used. Install mod_ssl Install the mod_ssl module:

$ sudo yum install mod_ssl

mod_ssl provides encryption capabilities for the httpd Web server. Unencrypted content is transmitted in plain text which could be passively monitored and accessed by unauthorized parties. CCE-RHEL7-CCE-TBD Deploy mod_security The security module provides an application level firewall for httpd. Following its installation with the base ruleset, specific configuration advice can be found at http://www.modsecurity.org/ to design a policy that best matches the security needs of the web applications. Usage of mod_security is highly recommended for some environments, but it should be noted this module does not ship with Red Hat Enterprise Linux itself, and instead is provided via Extra Packages for Enterprise Linux (EPEL). For more information on EPEL please refer to http://fedoraproject.org/wiki/EPEL. Install mod_security Install the security module:

$ sudo yum install mod_security

mod_security provides an additional level of protection for the web server by enabling the administrator to implement content access policies and filters at the application layer. CCE-RHEL7-CCE-TBD Use Denial-of-Service Protection Modules Denial-of-service attacks are difficult to detect and prevent while maintaining acceptable access to authorized users. However, some traffic-shaping modules can be used to address the problem. Well-known DoS protection modules include:

mod_cband mod_bwshare mod_limitipconn mod_evasive

Denial-of-service prevention should be implemented for a web server if such a threat exists. However, specific configuration details are very dependent on the environment and often best left at the discretion of the administrator. Configure PHP Securely PHP is a widely-used and often misconfigured server-side scripting language. It should be used with caution, but configured appropriately when needed.

Review /etc/php.ini and make the following changes if possible:

# Do not expose PHP error messages to external users
display_errors = Off

# Enable safe mode
safe_mode = On

# Only allow access to executables in isolated directory
safe_mode_exec_dir = php-required-executables-path

# Limit external access to PHP environment
safe_mode_allowed_env_vars = PHP_

# Restrict PHP information leakage
expose_php = Off

# Log all errors
log_errors = On

# Do not register globals for input data
register_globals = Off

# Minimize allowable PHP post size
post_max_size = 1K

# Ensure PHP redirects appropriately
cgi.force_redirect = 0

# Disallow uploading unless necessary
file_uploads = Off

# Disallow treatment of file requests as fopen calls
allow_url_fopen = Off

# Enable SQL safe mode
sql.safe_mode = On

Configure Operating System to Protect Web Server The following configuration steps should be taken on the machine which hosts the web server, in order to provide as safe an environment as possible for the web server. Restrict File and Directory Access Minimize access to critical httpd files and directories. Set Permissions on the /var/log/httpd/ Directory Ensure that the permissions on the web server log directory is set to 700:

$ sudo chmod 700 /var/log/httpd/

This is its default setting. CM-7 Access to the web server's log files may allow an unauthorized user or attacker to access information about the web server or alter the server's log files. CCE-RHEL7-CCE-TBD Set Permissions on the /etc/httpd/conf/ Directory Set permissions on the web server configuration directory to 750:

$ sudo chmod 750 /etc/httpd/conf/

Access to the web server's configuration files may allow an unauthorized user or attacker to access information about the web server or alter the server's configuration files. CCE-RHEL7-CCE-TBD Set Permissions on All Configuration Files Inside /etc/httpd/conf/ Set permissions on the web server configuration files to 640:

$ sudo chmod 640 /etc/httpd/conf/*

CM-7 Access to the web server's configuration files may allow an unauthorized user or attacker to access information about the web server or to alter the server's configuration files. CCE-RHEL7-CCE-TBD Configure iptables to Allow Access to the Web Server By default, iptables blocks access to the ports used by the web server. To configure iptables to allow port 80 traffic one must edit /etc/sysconfig/iptables and /etc/sysconfig/ip6tables (if IPv6 is in use). Add the following line, ensuring that it appears before the final LOG and DROP lines for the INPUT chain:

-A INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT

To configure iptables to allow port 443 traffic one must edit /etc/sysconfig/iptables and /etc/sysconfig/ip6tables (if IPv6 is in use). Add the following line, ensuring that it appears before the final LOG and DROP lines for the INPUT chain:

-A INPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT

Run httpd in a chroot Jail if Practical Running httpd inside a chroot jail is designed to isolate the web server process to a small section of the filesystem, limiting the damage if it is compromised. Versions of Apache greater than 2.2.10 (such as the one included with RHEL 7) provide the ChrootDir directive. To run Apache inside a chroot jail in /chroot/apache, add the following line to /etc/httpd/conf/httpd.conf:

ChrootDir /chroot/apache

This necessitates placing all files required by httpd inside /chroot/apache , including httpd's binaries, modules, configuration files, and served web pages. The details of this configuration are beyond the scope of this guide. This may also require additional SELinux configuration. IMAP and POP3 Server Dovecot provides IMAP and POP3 services. It is not installed by default. The project page at http://www.dovecot.org contains more detailed information about Dovecot configuration. Disable Dovecot If the system does not need to operate as an IMAP or POP3 server, the dovecot software should be disabled and removed. Disable Dovecot Service The dovecot service can be disabled with the following command:

$ sudo systemctl disable dovecot

Running an IMAP or POP3 server provides a network-based avenue of attack, and should be disabled if not needed. CCE-RHEL7-CCE-TBD To check that the dovecot service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled dovecot

Output should indicate the dovecot service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled dovecot
disabled

Run the following command to verify dovecot is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active dovecot

If the service is not running the command will return the following output:

inactive

Uninstall dovecot Package The dovecot package can be uninstalled with the following command:

$ sudo yum erase dovecot

If there is no need to make the Dovecot software available, removing it provides a safeguard against its activation. CCE-RHEL7-CCE-TBD if rpm -qa | grep -q dovecot; then yum -y remove dovecot fi Run the following command to determine if the dovecot package is installed:

$ rpm -q dovecot

Configure Dovecot if Necessary If the system will operate as an IMAP or POP3 server, the dovecot software should be configured securely by following the recommendations below. Support Only the Necessary Protocols Dovecot supports the IMAP and POP3 protocols, as well as SSL-protected versions of those protocols. Configure the Dovecot server to support only the protocols needed by your site. Edit /etc/dovecot/dovecot.conf. Add or correct the following lines, replacing PROTOCOL with only the subset of protocols (imap, imaps, pop3, pop3s) required:

protocols = PROTOCOL

If possible, require SSL protection for all transactions. The SSL protocol variants listen on alternate ports (995 instead of 110 for pop3s, and 993 instead of 143 for imaps), and require SSL-aware clients. An alternate approach is to listen on the standard port and require the client to use the STARTTLS command before authenticating. Configuring Dovecot to only support the protocols the protocols needed by your site reduces the risk of an attacker using one of the unused protocols to base an attack. Enable SSL Support SSL should be used to encrypt network traffic between the Dovecot server and its clients. Users must authenticate to the Dovecot server in order to read their mail, and passwords should never be transmitted in clear text. In addition, protecting mail as it is downloaded is a privacy measure, and clients may use SSL certificates to authenticate the server, preventing another system from impersonating the server. Enable the SSL flag in /etc/dovecot.conf To allow clients to make encrypted connections the ssl flag in Dovecot's configuration file needs to be set to yes.

Edit /etc/dovecot/conf.d/10-ssl.conf and add or correct the following line:

ssl = yes

SSL encrypt network traffic between the Dovecot server and its clients protecting user credentials, mail as it is downloaded, and clients may use SSL certificates to authenticate the server, preventing another system from impersonating the server. CCE-RHEL7-CCE-TBD Configure Dovecot to Use the SSL Certificate file This option tells Dovecot where to find the the mail server's SSL Certificate.

Edit /etc/dovecot/conf.d/10-ssl.conf and add or correct the following line (note: the path below is the default path set by the Dovecot installation. If you are using a different path, ensure you reference the appropriate file):

ssl_cert = </etc/pki/dovecot/certs/dovecot.pem

SSL certificates are used by the client to authenticate the identity of the server, as well as to encrypt credentials and message traffic. Not using SSL to encrypt mail server traffic could allow unauthorized access to credentials and mail messages since they are sent in plain text over the network. CCE-RHEL7-CCE-TBD Configure Dovecot to Use the SSL Key file This option tells Dovecot where to find the the mail server's SSL Key.

Edit /etc/dovecot/conf.d/10-ssl.conf and add or correct the following line (note: the path below is the default path set by the Dovecot installation. If you are using a different path, ensure you reference the appropriate file):

ssl_key = </etc/pki/dovecot/private/dovecot.pem

SSL certificates are used by the client to authenticate the identity of the server, as well as to encrypt credentials and message traffic. Not using SSL to encrypt mail server traffic could allow unauthorized access to credentials and mail messages since they are sent in plain text over the network. CCE-RHEL7-CCE-TBD Disable Plaintext Authentication To prevent Dovecot from attempting plaintext authentication of clients, edit /etc/dovecot/conf.d/10-auth.conf and add or correct the following line:

disable_plaintext_auth = yes

Using plain text authentication to the mail server could allow an attacker access to credentials by monitoring network traffic. CCE-RHEL7-CCE-TBD Allow IMAP Clients to Access the Server The default iptables configuration does not allow inbound access to any services. This modification will allow remote hosts to initiate connections to the IMAP daemon, while keeping all other ports on the server in their default protected state. To configure iptables to allow port 143 traffic one must edit /etc/sysconfig/iptables and /etc/sysconfig/ip6tables (if IPv6 is in use). Add the following line, ensuring that it appears before the final LOG and DROP lines for the INPUT chain:

-A INPUT -m state --state NEW -p tcp --dport 143 -j ACCEPT

Samba(SMB) Microsoft Windows File Sharing Server When properly configured, the Samba service allows Linux machines to provide file and print sharing to Microsoft Windows machines. There are two software packages that provide Samba support. The first, samba-client, provides a series of command line tools that enable a client machine to access Samba shares. The second, simply labeled samba, provides the Samba service. It is this second package that allows a Linux machine to act as an Active Directory server, a domain controller, or as a domain member. Only the samba-client package is installed by default. Disable Samba if Possible Even after the Samba server package has been installed, it will remain disabled. Do not enable this service unless it is absolutely necessary to provide Microsoft Windows file and print sharing functionality. Disable Samba The smb service can be disabled with the following command:

$ sudo systemctl disable smb

1436 Running a Samba server provides a network-based avenue of attack, and should be disabled if not needed. CCE-RHEL7-CCE-TBD To check that the smb service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled smb

Output should indicate the smb service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled smb
disabled

Run the following command to verify smb is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active smb

If the service is not running the command will return the following output:

inactive

Configure Samba if Necessary All settings for the Samba daemon can be found in /etc/samba/smb.conf. Settings are divided between a [global] configuration section and a series of user created share definition sections meant to describe file or print shares on the system. By default, Samba will operate in user mode and allow client machines to access local home directories and printers. It is recommended that these settings be changed or that additional limitations be set in place. Restrict SMB File Sharing to Configured Networks Only users with local user accounts will be able to log in to Samba shares by default. Shares can be limited to particular users or network addresses. Use the hosts allow and hosts deny directives accordingly, and consider setting the valid users directive to a limited subset of users or to a group of users. Separate each address, user, or user group with a space as follows for a particular share or global:

[share]
  hosts allow = 192.168.1. 127.0.0.1
  valid users = userone usertwo @usergroup

It is also possible to limit read and write access to particular users with the read list and write list options, though the permissions set by the system itself will override these settings. Set the read only attribute for each share to ensure that global settings will not accidentally override the individual share settings. Then, as with the valid users directive, separate each user or group of users with a space:

[share]
  read only = yes
  write list = userone usertwo @usergroup

The Samba service is only required for sharing files and printers with Microsoft Windows workstations, and even then, other options may exist. Disable Root Access to SMB Shares Administrators should not use administrator accounts to access Samba file and printer shares. Disable the root user and the wheel administrator group:

[share]
  invalid users = root @wheel

If administrator accounts cannot be disabled, ensure that local machine passwords and Samba service passwords do not match. Typically, administrator access is required when Samba must create user and machine accounts and shares. Domain member servers and standalone servers may not need administrator access at all. If that is the case, add the invalid users parameter to [global] instead. CCE-RHEL7-CCE-TBD Require Client SMB Packet Signing, if using smbclient To require samba clients running smbclient to use packet signing, add the following to the [global] section of the Samba configuration file, /etc/samba/smb.conf:

client signing = mandatory

Requiring samba clients such as smbclient to use packet signing ensures they can only communicate with servers that support packet signing. Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit. CCE-RHEL7-CCE-TBD ###################################################################### #By Luke "Brisk-OH" Brisk #luke.brisk@boeing.com or luke.brisk@gmail.com ###################################################################### CLIENTSIGNING=$( grep -ic 'client signing' /etc/samba/smb.conf ) if [ "$CLIENTSIGNING" -eq 0 ]; then # Add to global section sed -i 's/\[global\]/\[global\]\n\n\tclient signing = mandatory/g' /etc/samba/smb.conf else sed -i 's/[[:blank:]]*client[[:blank:]]signing[[:blank:]]*=[[:blank:]]*no/ client signing = mandatory/g' /etc/samba/smb.conf fi To verify that Samba clients running smbclient must use packet signing, run the following command:

$ grep signing /etc/samba/smb.conf

The output should show:

client signing = mandatory

Require Client SMB Packet Signing, if using mount.cifs Require packet signing of clients who mount Samba shares using the mount.cifs program (e.g., those who specify shares in /etc/fstab). To do so, ensure signing options (either sec=krb5i or sec=ntlmv2i) are used.

See the mount.cifs(8) man page for more information. A Samba client should only communicate with servers who can support SMB packet signing. Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit. CCE-RHEL7-CCE-TBD To verify that Samba clients using mount.cifs must use packet signing, run the following command:

$ grep sec /etc/fstab

The output should show either krb5i or ntlmv2i in use. Restrict Printer Sharing By default, Samba utilizes the CUPS printing service to enable printer sharing with Microsoft Windows workstations. If there are no printers on the local machine, or if printer sharing with Microsoft Windows is not required, disable the printer sharing capability by commenting out the following lines, found in /etc/samba/smb.conf:

[global]
  load printers = yes
  cups options = raw
[printers]
  comment = All Printers
  path = /usr/spool/samba
  browseable = no
  guest ok = no
  writable = no
  printable = yes

There may be other options present, but these are the only options enabled and uncommented by default. Removing the [printers] share should be enough for most users. If the Samba printer sharing capability is needed, consider disabling the Samba network browsing capability or restricting access to a particular set of users or network addresses. Set the valid users parameter to a small subset of users or restrict it to a particular group of users with the shorthand @. Separate each user or group of users with a space. For example, under the [printers] share:

[printers]
  valid users = user @printerusers

The Samba service is only required for sharing files and printers with Microsoft Windows workstations, and even then, other options may exist. Do not use the Samba service to share files between Unix or Linux machines. Proxy Server A proxy server is a very desirable target for a potential adversary because much (or all) sensitive data for a given infrastructure may flow through it. Therefore, if one is required, the machine acting as a proxy server should be dedicated to that purpose alone and be stored in a physically secure location. The system's default proxy server software is Squid, and provided in an RPM package of the same name. Disable Squid if Possible If Squid was installed and activated, but the system does not need to act as a proxy server, then it should be disabled and removed. Disable Squid The squid service can be disabled with the following command:

$ sudo systemctl disable squid

Running proxy server software provides a network-based avenue of attack, and should be removed if not needed. CCE-RHEL7-CCE-TBD To check that the squid service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled squid

Output should indicate the squid service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled squid
disabled

Run the following command to verify squid is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active squid

If the service is not running the command will return the following output:

inactive

Uninstall squid Package The squid package can be removed with the following command:

$ sudo yum erase squid

If there is no need to make the proxy server software available, removing it provides a safeguard against its activation. CCE-RHEL7-CCE-TBD Run the following command to determine if the squid package is installed:

$ rpm -q squid

SNMP Server The Simple Network Management Protocol allows administrators to monitor the state of network devices, including computers. Older versions of SNMP were well-known for weak security, such as plaintext transmission of the community string (used for authentication) and usage of easily-guessable choices for the community string. Disable SNMP Server if Possible The system includes an SNMP daemon that allows for its remote monitoring, though it not installed by default. If it was installed and activated but is not needed, the software should be disabled and removed. Disable snmpd Service The snmpd service can be disabled with the following command:

$ sudo systemctl disable snmpd

Running SNMP software provides a network-based avenue of attack, and should be disabled if not needed. CCE-RHEL7-CCE-TBD To check that the snmpd service is disabled in system boot configuration, run the following command:

$ systemctl is-enabled snmpd

Output should indicate the snmpd service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

$ systemctl is-enabled snmpd
disabled

Run the following command to verify snmpd is not active (i.e. not running) through current runtime configuration:

$ systemctl is-active snmpd

If the service is not running the command will return the following output:

inactive

Uninstall net-snmp Package The net-snmp package provides the snmpd service. The net-snmp package can be removed with the following command:

$ sudo yum erase net-snmp

If there is no need to run SNMP server software, removing the package provides a safeguard against its activation. CCE-RHEL7-CCE-TBD if rpm -qa | grep -q net-snmp; then yum -y remove net-snmp fi Run the following command to determine if the net-snmp package is installed:

$ rpm -q net-snmp

Configure SNMP Server if Necessary If it is necessary to run the snmpd agent on the system, some best practices should be followed to minimize the security risk from the installation. The multiple security models implemented by SNMP cannot be fully covered here so only the following general configuration advice can be offered:

    use only SNMP version 3 security models and enable the use of authentication and encryption
    write access to the MIB (Management Information Base) should be allowed only if necessary
    all access to the MIB should be restricted following a principle of least privilege
    network access should be limited to the maximum extent possible including restricting to expected network addresses both in the configuration files and in the system firewall rules
    ensure SNMP agents send traps only to, and accept SNMP queries only from, authorized management stations
    ensure that permissions on the snmpd.conf configuration file (by default, in /etc/snmp) are 640 or more restrictive
    ensure that any MIB files' permissions are also 640 or more restrictive

Configure SNMP Service to Use Only SNMPv3 or Newer Edit /etc/snmp/snmpd.conf, removing any references to rocommunity, rwcommunity, or com2sec. Upon doing that, restart the SNMP service:

$ sudo service snmpd restart

Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information. CCE-RHEL7-CCE-TBD To ensure only SNMPv3 or newer is used, run the following command:

$ sudo grep 'rocommunity\|rwcommunity\|com2sec' /etc/snmp/snmpd.conf | grep -v "^#"

There should be no output. Ensure Default Password Is Not Used Edit /etc/snmp/snmpd.conf, remove default community string public. Upon doing that, restart the SNMP service:

$ sudo service snmpd restart

Test attestation on 20121214 by MAN Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system. CCE-RHEL7-CCE-TBD To ensure the default password is not set, run the following command:

$ sudo grep -v "^#" /etc/snmp/snmpd.conf| grep public

There should be no output. Documentation to Support DISA OS SRG Mapping These groups exist to document how the Red Hat Enterprise Linux product meets (or does not meet) requirements listed in the DISA OS SRG, for those cases where Groups or Rules elsewhere in scap-security-guide do not clearly relate. Product Meets this Requirement This requirement is a permanent not a finding. No fix is required. 42 56 206 1084 66 85 86 185 223 171 172 1694 770 804 162 163 164 345 346 1096 1111 1291 386 156 186 1083 1082 1090 804 1127 1128 1129 1248 1265 1314 1362 1368 1310 1311 1328 1399 1400 1404 1405 1427 1499 1632 1693 1665 1674 Red Hat Enterprise Linux meets this requirement through design and implementation. RHEL7 supports this requirement and cannot be configured to be out of compliance. This is a permanent not a finding. Product Meets this Requirement This requirement is a permanent not a finding. No fix is required. 130 157 131 132 133 134 135 159 174 The Red Hat Enterprise Linux audit system meets this requirement through design and implementation. The RHEL7 auditing system supports this requirement and cannot be configured to be out of compliance. Every audit record in RHEL includes a timestamp, the operation attempted, success or failure of the operation, the subject involved (executable/process), the object involved (file/path), and security labels for the subject and object. It also includes the ability to label events with custom key labels. The auditing system centralizes the recording of audit events for the entire system and includes reduction (ausearch), reporting (aureport), and real-time response (audispd) facilities. This is a permanent not a finding. Product Meets this Requirement This requirement is a permanent not a finding. No fix is required. 34 35 99 154 226 802 872 1086 1087 1089 1091 1424 1426 1428 1209 1214 1237 1269 1338 1425 1670 Red Hat Enterprise Linux meets this requirement through design and implementation. RHEL7 supports this requirement and cannot be configured to be out of compliance. This is a permanent not a finding. Guidance Does Not Meet this Requirement Due to Impracticality or Scope This requirement is NA. No fix is required. 21 25 28 29 30 165 221 354 553 779 780 781 1009 1094 1123 1124 1125 1132 1135 1140 1141 1142 1143 1145 1147 1148 1166 1339 1340 1341 1350 1356 1373 1374 1383 1391 1392 1395 1662 The guidance does not meet this requirement. The requirement is impractical or out of scope. RHEL7 cannot support this requirement without assistance from an external application, policy, or service. This requirement is NA. Implementation of the Requirement is Not Supported This requirement is a permanent finding and cannot be fixed. An appropriate mitigation for the system must be implemented but this finding cannot be considered fixed. 20 31 52 144 1158 1294 1295 1500 RHEL7 does not support this requirement. This is a permanent finding. Guidance Does Not Meet this Requirement Due to Impracticality or Scope This requirement is NA. No fix is required. 15 27 218 219 371 372 535 537 539 1682 370 37 24 1112 1126 1143 1149 1157 1159 1210 1211 1274 1372 1376 1377 1352 1401 1555 1556 1150 The guidance does not meet this requirement. The requirement is impractical or out of scope. RHEL7 cannot support this requirement without assistance from an external application, policy, or service. This requirement is NA. A process for prompt installation of OS updates must exist. Procedures to promptly apply software updates must be established and executed. The Red Hat operating system provides support for automating such a process, by running the yum program through a cron job or by managing the system and its packages through the Red Hat Network or a Satellite Server. 1232 This is a manual inquiry about update procedure. Ask an administrator if a process exists to promptly and automatically apply OS software updates. If such a process does not exist, this is a finding.

If the OS update process limits automatic updates of software packages, where such updates would impede normal system operation, to scheduled maintenance windows, but still within IAVM-dictated timeframes, this is not a finding. 