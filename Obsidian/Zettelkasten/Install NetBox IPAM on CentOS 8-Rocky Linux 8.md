		{{date:YYYYMMDD}}/{{time:HHmm}}

		Status:#idea
		
		Tags:

		# {{# Install NetBox IPAM on CentOS 8|Rocky Linux 8}}


By

[Klinsmann Öteyo](https://computingforgeeks.com/author/klinsmann/)

-

November 26, 2021

Netbox is a free and open-source tool used to manage and document computer networks via the web. This has helped reduce the tedious task of networking in organizations by creating a virtual implementation of every device in a data center. Back in the day, this task was done by drawing the network structure on paper but with NetBox, organized and presentable operations are visualized via the web.

Netbox is written in Django and uses the PostgreSQL database to document computer networks and manage IP addresses. It has the following amazing features:

1.  IPAM – IP Address Management
2.  Vlan Management
3.  Rack Elevation
4.  VRF Management
5.  Multi-Site (tenancy)
6.  Connection Management – Interfaces/Console/Power
7.  Customization Header For Logo’s etc
8.  Circuit Provider Management
9.  Single Converged Database
10.  DCIM – Data Center Infrastructure Management
11.  Report Alert

## Step 1: Update System and Install dependencies

In this guide, we will install and configure NetBox IPAM Tool on Rocky Linux 8. For this guide, you will require:

1.  A Rocky Linux 8 system.
2.  A user with sudo privileges.

Update your system.

```
sudo yum update
```

Install the EPEL repository required for installing dependencies.

```
sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
```

Install the required dependencies.

```
sudo yum groupinstall "Development Tools" -y
sudo yum install -y vim gcc zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel openssl-devel tk-devel libffi-devel xz-devel gdbm-devel ncurses-devel wget supervisor
```

Set SELinux in permissive mode since we will be using TCP ports.

```
sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
cat /etc/selinux/config | grep SELINUX=
```

## Step 2: Install Python on Rocky Linux 8|CentOS 8

In this guide, we will install Python 3.7 since this version of Netbox IPAM requires Python 3.7 and above. Download Python 3.7 as below

```
wget https://www.python.org/ftp/python/3.7.12/Python-3.7.12.tgz
```

Extract the archive.

```
tar xzf Python-3.7.12.tgz
```

Navigate to the extracted directory and optimize as below.

```
cd Python-3.7.12
sudo ./configure --enable-optimizations
```

Then install Python 3.7 on Rocky Linux as below.

```
sudo make altinstall
```

Identify the path to python.

```
$ whereis python3.7
python3: /usr/bin/python3.6m /usr/bin/python3.6 /usr/bin/python3 /usr/lib/python3.6 /usr/lib64/python3.6 /usr/local/bin/python3.7m /usr/local/bin/python3.7 /usr/local/bin/python3.7m-config /usr/local/lib/python3.7 /usr/local/lib/python3.6 /usr/include/python3.6m /opt/netbox/venv/bin/python3 /usr/share/man/man1/python3.1.gz
```

Create a symbolic link to **/usr/bin/python**. If there already exists a link, remove the existing file `sudo rm -rf /usr/bin/python3` and `pip3` as well

```
sudo ln -fs /usr/local/bin/python3.7 /usr/bin/python3
sudo ln -fs /usr/local/bin/pip3.7 /usr/bin/pip3
```

Verify the installed version.

```
$ python3 --version
Python 3.7.12
```

## Step 3: Install and configure PostgreSQL database server

Since Netbox IPAM uses the PostgreSQL database, it is required that we install it on Rocky Linux. First, check the latest available version.

```
$ sudo dnf module list postgresql
Rocky Linux 8 - AppStream
Name         Stream   Profiles             Summary                              
postgresql   9.6      client, server [d]   PostgreSQL server and client module  
postgresql   10 [d]   client, server [d]   PostgreSQL server and client module  
postgresql   12       client, server [d]   PostgreSQL server and client module  
postgresql   13       client, server [d]   PostgreSQL server and client module  

Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled
```

From the output, we will install version 13. Enable it as below

```
$ sudo dnf module enable postgresql:13
......
Dependencies resolved.
================================================================================
 Package           Architecture     Version             Repository         Size
================================================================================
Enabling module streams:
 postgresql                         13                                         

Transaction Summary
================================================================================

Is this ok [y/N]: y
```

The proceed and install the enabled PostgreSQL version.

```
sudo dnf install postgresql-server
```

Initialize PostgreSQL.

```
sudo postgresql-setup --initdb
```

With a successful installation, start and enable PostgreSQL to run on boot.

```
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

Now create a database for NetBox IPAM.

```
sudo -u postgres psql
```

While in the PostgreSQL shell, create a database as below.

```
CREATE DATABASE netbox;
CREATE USER netbox WITH PASSWORD 'Passw0rd';
GRANT ALL PRIVILEGES ON DATABASE netbox TO netbox;
\q
```

Enable password login in PostgreSQL.

```
sudo sed -i -e 's/ident/md5/' /var/lib/pgsql/data/pg_hba.conf
sudo systemctl restart postgresql
```

Confirm if you can log in to the database created using the password set.

```
$ psql -U netbox -h localhost -W
Password: <Input-Password>
psql (13.3)
Type "help" for help.

netbox=> \q
```

## Step 4: Install and Configure Netbox on Rocky Linux 8|CentOS 8

Now we have come to the nub of this guide where we are required to clone NetBox IPAM from git and configure it on Rocky Linux 8|CentOS 8.

First, navigate to the /opt/ directory and clone NetBox.

```
cd /opt/
sudo git clone -b master https://github.com/digitalocean/netbox.git
```

Now create a configuration file for Netbox.

```
cd netbox/netbox/netbox/
sudo cp configuration.example.py configuration.py
```

Now edit the configuration file.

```
sudo vim configuration.py
```

Edit the file as below.

```
# Example: ALLOWED_HOSTS = ['netbox.example.com', 'netbox.internal.local']
ALLOWED_HOSTS = ['127.0.0.1']

# PostgreSQL database configuration.
DATABASE = {
    'NAME': 'netbox',                           # Database name you created
    'USER': 'netbox',                           # PostgreSQL username you created
    'PASSWORD': 'Passw0rd',               # PostgreSQL password you set
    'HOST': 'localhost',                        # Database server
    'PORT': '',                                 # Database port (leave blank for default)
    'CONN_MAX_AGE': 300,                        # Max database connection age
}
```

### Create a Python Virtual Environment.

We will create a virtual environment for python as below.

```
cd /opt/netbox/
sudo python3 -m venv /opt/netbox/venv
```

Proceed and activate the environment and install the required packages.

```
source venv/bin/activate
```

While in the environment, issue the commands below.

```
sudo python3 -m pip install -U pip
sudo python3 -m pip install -U setuptools
sudo pip3 install -r /opt/netbox/requirements.txt
sudo pip3 install --upgrade PyYAML --ignore-installed
```

Modify the Django path.

```
$ sudo vim /etc/profile.d/local_python.sh
PYTHONPATH="/usr/local/lib/python3.7/site-packages/":"${PYTHONPATH}"
export PYTHONPATH 
$ source /etc/profile.d/local_python.sh
```

### Generate the Django Secret Key

Now generate the Django SECRET Key as below.

```
cd /opt/netbox/netbox
./generate_secret_key.py
```

Sample Output:

```
D16W@QzSD#Azhy4WxPsZ2kCn*I7lJ@7s$wp1^+6k5M^^=O@gUq
```

With the key generated, proceed and set it in the **configuration.py** as below.

```
$ sudo vim /opt/netbox/netbox/netbox/configuration.py
# https://docs.djangoproject.com/en/stable/ref/settings/#std:setting-SECRET_KEY
SECRET_KEY = 'D16W@QzSD#Azhy4WxPsZ2kCn*I7lJ@7s$wp1^+6k5M^^=O@gUq'
```

### Create Schemas

Create the schema for Netbox IPAM. This is achieved by running the migrate.py from the Netbox directory as below.

```
cd /opt/netbox/netbox/
sudo python3 manage.py migrate
```

Sample Output:

```
Operations to perform:
  Apply all migrations: admin, auth, circuits, contenttypes, dcim, extras, ipam, sessions, taggit, tenancy, users, virtualization
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying admin.0003_logentry_add_action_flag_choices... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
.....
 OK
  Applying ipam.0049_prefix_mark_utilized... OK
  Applying ipam.0050_iprange... OK
  Applying sessions.0001_initial... OK
  Applying taggit.0001_initial... OK
  Applying taggit.0002_auto_20150616_2121... OK
  Applying taggit.0003_taggeditem_add_unique_index... OK
  Applying tenancy.0002_tenant_ordering... OK
  Applying users.0001_squashed_0011... OK
  Applying virtualization.0023_virtualmachine_natural_ordering... OK
```

### Create Netbox User Account.

The next step requires us to create a superuser account since Netbox doesn’t come with predefined user accounts. From the Netbox directory execute the command

```
sudo python3 manage.py createsuperuser
```

Proceed as below.

```
Username (leave blank to use 'thor'): admin
Email address: admin@computingforgeeks.com
Password: 
Password (again): 
Superuser created successfully.
```

Proceed and move static files as below.

```
(venv) [thor@lo.. netbox]$ sudo python3 manage.py collectstatic
240 static files copied to '/opt/netbox/netbox/static'.
```

### Install and configure the Gunicorn module

Install the **Gunicorn** python module using PIP as below.

```
$ sudo pip3 install gunicorn
Requirement already satisfied: gunicorn in /usr/local/lib/python3.7/site-packages (20.1.0)
Requirement already satisfied: setuptools>=3.0 in /usr/local/lib/python3.7/site-packages (from gunicorn) (58.3.0)
```

Then configure Gunicorn

```
sudo cp /opt/netbox/contrib/gunicorn.py /opt/netbox/gunicorn_config.py
sudo vim /opt/netbox/gunicorn_config.py
```

In the file, add the below lines.

```
command = '/usr/local/bin/gunicorn'
pythonpath = '/opt/netbox/netbox'
bind = '127.0.0.1:8001'
workers = 3
user = 'netbox'
# The maximum number of requests a worker can handle before being respawned
max_requests = 5000
max_requests_jitter = 500
```

Next, configure a supervisor file.

```
$ sudo vim /etc/supervisord.d/netbox.ini
[program:netbox]
command = gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi
directory = /opt/netbox/netbox/
user = netbox
```

Add the Netbox system user.

```
sudo groupadd --system netbox
sudo useradd --system netbox -g netbox
sudo chown --recursive netbox /opt/netbox/netbox/media/
```

Start and enable the supervisor service.

```
sudo systemctl enable supervisord
sudo systemctl restart supervisord
```

Confirm service status using systemctl command:

```
$ systemctl status supervisord
● supervisord.service - Process Monitoring and Control Daemon
   Loaded: loaded (/usr/lib/systemd/system/supervisord.service; enabled; vendor preset: disabled)
   Active: active (running) since Mon 2021-11-08 12:34:55 UTC; 10s ago
  Process: 118629 ExecStart=/usr/bin/supervisord -c /etc/supervisord.conf (code=exited, status=0/SUCCESS)
 Main PID: 118632 (supervisord)
    Tasks: 7 (limit: 23473)
   Memory: 421.7M
   CGroup: /system.slice/supervisord.service
           ├─118632 /usr/bin/python3.6 /usr/bin/supervisord -c /etc/supervisord.conf
           ├─118633 /bin/python3 /usr/local/bin/gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi
           ├─118636 /bin/python3 /usr/local/bin/gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi
           ├─118637 /bin/python3 /usr/local/bin/gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi
           ├─118638 /bin/python3 /usr/local/bin/gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi
           ├─118639 /bin/python3 /usr/local/bin/gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi
           └─118640 /bin/python3 /usr/local/bin/gunicorn -c /opt/netbox/gunicorn_config.py netbox.wsgi

Nov 08 12:34:54 rocky.hirebestengineers.com systemd[1]: Starting Process Monitoring and Control Daemon...
Nov 08 12:34:55 rocky.hirebestengineers.com systemd[1]: Started Process Monitoring and Control Daemon.
```

The service should be running on port 8001.

```
$ ss -tunelp | grep 8001
tcp   LISTEN 0      128        127.0.0.1:8001      0.0.0.0:*    uid:993 ino:24304646 sk:1e <->
```

Install and start the Redis server.

```
sudo yum -y install redis
sudo systemctl start redis
```

## Step 5: Install and Configure Httpd or Nginx for Netbox IPAM

In this guide, we will be showing the configuration on both Apache and the Nginx web server.

### For Nginx web server

Install Nginx web-server on Rocky Linux 8 with the command.

```
sudo yum -y install nginx
```

We will first create a virtual host file for our web page.

```
sudo vim /etc/nginx/conf.d/netbox.conf
```

In the file, add the below lines. Replace **_netbox.example.com_** with your FQDN or IP_address.

```
server {
    listen 80;
    server_name netbox.example.com;
    client_max_body_size 25m;

    location /static/ {
        alias /opt/netbox/netbox/static/;
    }

    location / {
        proxy_pass http://127.0.0.1:8001;
    }
}
```

Check the syntax of the file created.

```
$ sudo nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Start and enable Nginx to run on boot.

```
sudo systemctl start nginx
sudo systemctl enable nginx
```

Allow port 80 through the firewall.

```
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload
```

Allow port 8001 on SELinux.

```
sudo semanage port -a -t dns_port_t -p tcp 8001
```

If you are using firewalld, allow the port through the firewall.

```
sudo firewall-cmd --permanent --add-port={80,443}/tcp
sudo firewall-cmd --reload
```

## Step 6: Access the Netbox IPAM Tool Web UI.

With everything configured accordingly, we are now set to access the Netbox IPAM web interface using the URL [http://Hostname](http://hostname/) or [http://IP_Address](http://ip_add/). You will be granted this page.

[![Install and Configure NetBox IPAM Tool on Rocky Linux 8](https://computingforgeeks.com/wp-content/uploads/2021/10/Install-and-Configure-NetBox-IPAM-Tool-on-Rocky-Linux-8-1024x534.png?ezimgfmt=rs:696x363/rscb23/ng:webp/ngcb23 "Install NetBox IPAM on CentOS 8|Rocky Linux 8 1")](data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%221024%22 height=%22534%22%3E%3C/svg%3E)

To make changes, you need to be logged in. Click “**Log in”** in the right corner. Enter the credentials created for the superuser account in **step 2** above.

[![Install and Configure NetBox IPAM Tool on Rocky Linux 8 1](https://computingforgeeks.com/wp-content/uploads/2021/10/Install-and-Configure-NetBox-IPAM-Tool-on-Rocky-Linux-8-1.png?ezimgfmt=rs:517x378/rscb23/ng:webp/ngcb23 "Install NetBox IPAM on CentOS 8|Rocky Linux 8 2")](data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22517%22 height=%22378%22%3E%3C/svg%3E)

On successful login, you will be granted this window.

[![Install and Configure NetBox IPAM Tool on Rocky Linux 8 2](https://computingforgeeks.com/wp-content/uploads/2021/10/Install-and-Configure-NetBox-IPAM-Tool-on-Rocky-Linux-8-2-1024x493.png?ezimgfmt=rs:696x335/rscb23/ng:webp/ngcb23 "Install NetBox IPAM on CentOS 8|Rocky Linux 8 3")](data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%221024%22 height=%22493%22%3E%3C/svg%3E)

While here, you can navigate to the panel on the left side as below.

[![Install and Configure NetBox IPAM Tool on Rocky Linux 8 6](https://computingforgeeks.com/wp-content/uploads/2021/10/Install-and-Configure-NetBox-IPAM-Tool-on-Rocky-Linux-8-6-1024x501.png?ezimgfmt=rs:696x341/rscb23/ng:webp/ngcb23 "Install NetBox IPAM on CentOS 8|Rocky Linux 8 4")](data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%221024%22 height=%22501%22%3E%3C/svg%3E)

From the panel, you can add devices, connections, IPAM, clusters, circuits, power supply, and other options. This simply implies that with Netbox, one can fully manage a data center by adding the required devices here. For example, to add a device, you will be required to enter information as below.

[![Install and Configure NetBox IPAM Tool on Rocky Linux 8 4](https://computingforgeeks.com/wp-content/uploads/2021/10/Install-and-Configure-NetBox-IPAM-Tool-on-Rocky-Linux-8-4.png?ezimgfmt=rs:696x390/rscb23/ng:webp/ngcb23 "Install NetBox IPAM on CentOS 8|Rocky Linux 8 5")](data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22984%22 height=%22552%22%3E%3C/svg%3E)

## Conclusion.

That is it for now. I hope you found this guide on how to install and configure NetBox IPAM Tool on Rocky Linux 8 enjoyable.


		--
		# References
		