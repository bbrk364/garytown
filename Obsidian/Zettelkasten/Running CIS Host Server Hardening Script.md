## Running CIS Host Server Hardening Script

#***********************************************************
# Apt Update
#***********************************************************

sudo apt update -y

#***********************************************************
# Install ansible
#***********************************************************

sudo apt install -y ansible


#***********************************************************
# Create or append ansible requirements file
#***********************************************************

sudo sh -c "echo '- src: https://github.com/florianutz/Ubuntu1804-CIS.git' >> /etc/ansible/requirements.yml"


#***********************************************************
# Install the role for CIS Ubuntu script from Github
#***********************************************************

cd /etc/ansible/
sudo ansible-galaxy install -p roles -r /etc/ansible/requirements.yml

#***********************************************************
# Create Ansible Playbook for CIS Ubuntu script
#***********************************************************

sudo sh -c "cat > /etc/ansible/harden.yml <<EOF
- name: Harden Server
  hosts: localhost
  connection: local
  become: yes

  roles:
    - Ubuntu1804-CIS
    
EOF
"


#***********************************************************
# Run ansible playbook file
# DO NOT RUN ON PRODUCTION!!!!
#***********************************************************

sudo ansible-playbook /etc/ansible/harden.yml


#***********************************************************
# Restart SSH. You will lose the ability to ssh as root!
#***********************************************************

sudo systemctl restart sshd

## 1.3 Automatic Upgrades

We dont want to be stuck constantly maintaining and doing updates on our server. Especially when we are backing up the WordPress site itself and we have VM level backups.

So we will configure updates to be automatic for the best results of host server hardening.

Change the email address and run this script to configure automatic updates with detailed email reports. When installing Postfix, just choose the defaults.

***********************************************************
# Install postfix and Unattended Upgrades
#***********************************************************

sudo apt install -y unattended-upgrades
sudo apt install -y postfix

#***********************************************************
# Edit Config file
#***********************************************************

sudo sed -i '/Unattended-Upgrade::Skip-Updates-On-Metered-Connections "true"/a\\Unattended-Upgrade::Mail "youremail@domain.com";
' /etc/apt/apt.conf.d/50unattended-upgrades

sudo sed -i '/Unattended-Upgrade::Skip-Updates-On-Metered-Connections "true"/a\\Unattended-Upgrade::Remove-Unused-Dependencies "true";' /et$

sudo sed -i '/Unattended-Upgrade::Skip-Updates-On-Metered-Connections "true"/a\\        "${distro_id}:${distro_codename}-updates";
' /etc/apt/apt.conf.d/50unattended-upgrades


#***********************************************************
# Create additonal config file
#***********************************************************

sudo sh -c "cat > /tmp/20auto-upgrades <<\EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
"

#***********************************************************
# Copy Config file
#***********************************************************


sudo sh -c "cp -f /tmp/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades"
sudo sh -c "rm -f /tmp/20auto-upgrades"


#***********************************************************
# Copy Config file
#***********************************************************

sudo apt -y install apticron
sudo sed -i '/EMAIL="root"/c\EMAIL="youremail@domain.com"' /etc/apticron/apticron.conf 

#***********************************************************
# Enable and run Unattended-Upgrades
#***********************************************************

sudo systemctl enable unattended-upgrades
sudo apt -y update
sudo unattended-upgrades

