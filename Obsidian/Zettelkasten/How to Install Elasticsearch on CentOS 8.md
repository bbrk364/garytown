		{{date:YYYYMMDD}}/{{time:HHmm}}

		Status:#idea
		
		Tags:

		#{{How to Install Elasticsearch on CentOS 8}}
Elasticsearch is an open-source distributed full-text search and analytics engine. It supports RESTful operations and allows you to store, search, and analyze big volumes of data in real-time. Elasticsearch is one of the most popular search engines powering applications that have complex search requirements such as big e-commerce stores and analytic applications.

This tutorial covers the installation of Elasticsearch on CentOS 8.

## Installing Java

Elasticsearch is a Java application, so the first step is to install Java.

Run the following as root or user with [sudo privileges](https://linuxize.com/post/how-to-add-user-to-sudoers-in-centos/) command to install the OpenJDK package:

```
sudo dnf install java-11-openjdk-devel
```

Verify the Java installation by printing the [Java version](https://linuxize.com/post/how-to-check-java-version/) :

```
java -version
```

The output should look something like this:

```output
openjdk version "11.0.5" 2019-10-15 LTS
OpenJDK Runtime Environment 18.9 (build 11.0.5+10-LTS)
OpenJDK 64-Bit Server VM 18.9 (build 11.0.5+10-LTS, mixed mode, sharing)
```

## Installing Elasticsearch

Elasticsearch is not available in the standard CentOS 8 repositories. We’ll install it from the Elasticsearch RPM repository.

Import the repository’s GPG using the [`rpm`](https://linuxize.com/post/rpm-command-in-linux/) command:

```
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```

Open your text editor and create the repository file the `/etc/yum.repos.d` directory:

```
sudo nano /etc/yum.repos.d/elasticsearch.repo
```

Paste the following content into the file:

/etc/yum.repos.d/elasticsearch.repo

```ini
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
```

Copy

Save the file and close your text editor.

At the time of writing this article, the latest version of Elasticsearch is `7.6`. If you want to install a previous version of Elasticsearch, change `7.x` in the command above with the version you need.

Now that the repository is enabled, install the Elasticsearch package by typing:

```
sudo dnf install elasticsearch
```

Once the installation process is complete, start, and enable the service:

```
sudo systemctl enable elasticsearch.service --now
```

To verify that Elasticsearch is running, use [`curl`](https://linuxize.com/post/curl-command-examples/) to send an HTTP request to port 9200 on localhost:

```
curl -X GET "localhost:9200/"
```

The output will look something like this:

```output
{
  "name" : "centos8.localdomain",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "V_mfjn2PRJqX3PlZb_VD7w",
  "version" : {
    "number" : "7.6.0",
    "build_flavor" : "default",
    "build_type" : "rpm",
    "build_hash" : "7f634e9f44834fbc12724506cc1da681b0c3b1e3",
    "build_date" : "2020-02-06T00:09:00.449973Z",
    "build_snapshot" : false,
    "lucene_version" : "8.4.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
```

It may take 5-10 seconds for the service to start. If you see `curl: (7) Failed to connect to localhost port 9200: Connection refused`, wait for a few seconds and try again.

To view the messages logged by the Elasticsearch service, use the following command:

```
sudo journalctl -u elasticsearch
```

At this point, you have Elasticsearch installed on your CentOS server.

## Configuring Elasticsearch

Elasticsearch data is stored in the `/var/lib/elasticsearch` directory, configuration files are located in `/etc/elasticsearch`.

By default, Elasticsearch is configured to listen on localhost only. If the client connecting to the database is also running on the same host and you are setting up a single node cluster, you don’t need to change the default configuration file.

### Remote Access

Out of box Elasticsearch, does not implement authentication, so it can be accessed by anyone who can access the HTTP API. If you want to allow remote access to your Elasticsearch server, you will need to configure your [firewall](https://linuxize.com/post/how-to-configure-and-manage-firewall-on-centos-8/) and allow access to the Elasticsearch port 9200 only from trusted clients.

For example, to allow connections only from `192.168.121.80`, enter the following command:

Run the following command to allow assess from the remote trusted IP address on port `9200` :

```
sudo firewall-cmd --new-zone=elasticsearch --permanent
```

Do not forget to change `192.168.121.80` with your remote IP Address.

Later, if you want to allow access from another IP Address use:

```
sudo firewall-cmd --zone=elasticsearch --add-source=<IP_ADDRESS> --permanent
```

Once the firewall is configured, the next step is to edit the Elasticsearch configuration and allow Elasticsearch to listen for external connections.

To do so, open the `elasticsearch.yml` configuration file:

```
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Search for the line that contains `network.host`, uncomment it, and change the value to `0.0.0.0`:

/etc/elasticsearch/elasticsearch.yml

```ini
network.host: 0.0.0.0
```

Copy

If you have multiple network interfaces on your machine, specify the interface IP address to force Elasticsearch to listen only to the given interface.

Restart the Elasticsearch service for the changes to take effect:

```
sudo systemctl restart elasticsearch
```

That’s it. You can now connect to the Elasticsearch server from the remote location.

## Conclusion

We’ve shown you how to install Elasticsearch on CentOS 8.

To learn more about Elasticsearch, visit the official [documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/getting-started.html) page.


		--
		# References
		