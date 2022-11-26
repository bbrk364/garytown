		{{date:YYYYMMDD}}/{{time:HHmm}}

		Status:#idea
		
		Tags:

		# {{# How to Install Apache Cassandra on CentOS 8}}

Apache Cassandra is a free and open-source NoSQL database with no single point of failure. It provides linear scalability and high availability without compromising performance. Apache Cassandra is used by many companies that have large, active data sets, including Reddit, NetFlix, Instagram, and Github.

This article explains how to install Apache Cassandra on CentOS 8.

## Installing Apache Cassandra

The easiest way to install Apache Cassandra on CentOS 8 is by [installing the rpm package](https://linuxize.com/post/how-to-install-rpm-packages-on-centos/) from the official Apache Cassandra repository.

The latest version of Apache Cassandra is `3.11` and requires OpenJDK 8 to be installed on the system.

Run the following command as root or [user with sudo privileges](https://linuxize.com/post/how-to-add-user-to-sudoers-in-centos/) to [install OpenJDK](https://linuxize.com/post/install-java-on-centos-8/) :

```
sudo dnf install java-1.8.0-openjdk-devel
```

Once completed, verify the installation by printing the [Java version](https://linuxize.com/post/how-to-check-java-version/) :

```
java -version
```

The output should look something like this:

```output
openjdk version "1.8.0_262"
OpenJDK Runtime Environment (build 1.8.0_262-b10)
OpenJDK 64-Bit Server VM (build 25.262-b10, mixed mode)
```

Now that Java is installed, the next step is to add the Apache Cassandra repository.

Open your text editor and create the following repository file:

```
sudo nano /etc/yum.repos.d/cassandra.repo
```

Paste the following content into the file:

/etc/yum.repos.d/cassandra.repo

```ini
[cassandra]
name=Apache Cassandra
baseurl=https://www.apache.org/dist/cassandra/redhat/311x/
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://www.apache.org/dist/cassandra/KEYS
```

Copy

Save the file and install the latest version of Apache Cassandra by typing:

```
sudo dnf install cassandra
```

When prompted, type `y` to import the GPG keys.

Once the installation is completed, start and enable the Cassandra service:

```
sudo systemctl start cassandra
```

Verify that Cassandra is running by typing:

```
nodetool status
```

You should see something similar to this:

```output
Datacenter: datacenter1
=======================
Status=Up/Down
|/ State=Normal/Leaving/Joining/Moving
--  Address    Load       Tokens  Owns (effective)  Host ID                               Rack
UN  127.0.0.1  69.99 KiB  256     100.0%            ce0389a3-b48c-4cc9-b594-abe23e677d33  rack1
```

That’s it. At this point, you have Apache Cassandra installed on your CentOS server.

## Configuring Apache Cassandra

Apache Cassandra data is stored in the `/var/lib/cassandra` directory, configuration files are located in `/etc/cassandra` and Java start-up options can be configured in the `/etc/default/cassandra` file.

By default, Cassandra is configured to listen on localhost only. If the client connecting to the database is also running on the same host, you don’t need to change the default configuration file.

To interact with Cassandra through CQL (the Cassandra Query Language), you can use a command line utility named `cqlsh` that is shipped with the Cassandra package.

`cqlsh` requires Python 2 to be in the [system’s PATH](https://linuxize.com/post/how-to-add-directory-to-path-in-linux/) . If you don’t have [Python 2 installed](https://linuxize.com/post/how-to-install-python-on-centos-8/) on the server, you can do it with the following commands:

```
sudo dnf install python2
```

Once python is set up, run `cqlsh` to access the CQL shell:

```
cqlsh
```

```output
[cqlsh 5.0.1 | Cassandra 3.11.7 | CQL spec 3.4.4 | Native protocol v4]
Use HELP for help.
cqlsh> 
```

## Renaming Apache Cassandra Cluster

By default, the Cassandra cluster is named “Test Cluster”. If you want to change the cluster name, follow the steps below:

1.  Login to the Cassandra CQL terminal with `cqlsh`:
    
    ```
    cqlsh
    ```
    
    The following command will change the cluster name to “Linuxize Cluster”:
    
    ```sql
    UPDATE system.local SET cluster_name = 'Linuxize Cluster' WHERE KEY = 'local';
    ```
    
    Copy
    
    Replace “Linuxize Cluster” with your desired name. Once done, type `exit` to exit the console.
    
2.  Open the `cassandra.yaml` configuration file, search for “cluster_name” and enter your new cluster name:
    
    ```
    sudo nano /etc/cassandra/default.conf/cassandra.yaml
    ```
    
    /etc/cassandra/default.conf/cassandra.yaml
    
    ```yaml
    cluster_name: 'Linuxize Cluster'
    ```
    
    Copy
    
3.  Clear the system cache:
    
    ```
    nodetool flush system
    ```
    
4.  Finally restart the Cassandra service:
    
    ```
    sudo systemctl restart cassandra
    ```
    

## Conclusion

We’ve shown you how to install Apache Cassandra on CentOS 8. You can now visit the official [Apache Cassandra Documentation](https://cassandra.apache.org/doc/latest/getting_started/index.html) page and learn how to get started with Cassandra.

If you hit a problem or have feedback, leave a comment below.

		--
		# References
		