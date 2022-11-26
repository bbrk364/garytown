		{{date:YYYYMMDD}}/{{time:HHmm}}

		Status:#idea
		
		Tags:

		# {{# Secure Nginx with Let's Encrypt on CentOS 8}}
Let’s Encrypt is a free, automated, and open certificate authority developed by the Internet Security Research Group (ISRG) that provides free SSL certificates.

Certificates issued by Let’s Encrypt are trusted by all major browsers and valid for 90 days from the issue date.

In this tutorial, we’ll provide a step by step instructions about how to install a free Let’s Encrypt SSL certificate on CentOS 8 running Nginx as a web server. We’ll also show how to configure Nginx to use the SSL certificate and enable HTTP/2.

## Prerequisites

Before you proceed, make sure that you have met the following prerequisites:

-   You have a domain name pointing to your public IP. We’ll use `example.com`.
-   You have [Nginx installed](https://linuxize.com/post/how-to-install-nginx-on-centos-8/) on your CentOS server.
-   Your [firewall](https://linuxize.com/post/how-to-configure-and-manage-firewall-on-centos-8/) is configured to accept connections on ports 80 and 443.

## Installing Certbot

Certbot is a free command-line tool that simplifies the process for obtaining and renewing Let’s Encrypt SSL certificates from and auto-enabling HTTPS on your server.

The certbot package is not included in the standard CentOS 8 repositories, but it can be downloaded from the vendor’s website.

Run the following [`wget`](https://linuxize.com/post/wget-command-examples/) command as root or [sudo user](https://linuxize.com/post/create-a-sudo-user-on-centos/) to download the certbot script to the `/usr/local/bin` directory:

```
sudo wget -P /usr/local/bin https://dl.eff.org/certbot-auto
```

Once the download is complete, [make the file executable](https://linuxize.com/post/chmod-command-in-linux/) :

```
sudo chmod +x /usr/local/bin/certbot-auto
```

## Generating Strong Dh (Diffie-Hellman) Group

Diffie–Hellman key exchange (DH) is a method of securely exchanging cryptographic keys over an unsecured communication channel.

Generate a new set of 2048 bit DH parameters by typing the following command:

```
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
```

If you want you can change the key length up to 4096 bits, but the generation may take more than 30 minutes, depending on the system entropy.

## Obtaining a Let’s Encrypt SSL certificate

To obtain an SSL certificate for the domain, we’re going to use the Webroot plugin that works by creating a temporary file for validating the requested domain in the `${webroot-path}/.well-known/acme-challenge` directory. The Let’s Encrypt server makes HTTP requests to the temporary file to validate that the requested domain resolves to the server where certbot runs.

To make it more simple we’re going to map all HTTP requests for `.well-known/acme-challenge` to a single directory, `/var/lib/letsencrypt`.

The following commands will create the directory and make it writable for the Nginx server.

```
sudo mkdir -p /var/lib/letsencrypt/.well-known
```

To avoid duplicating code, create the following two snippets which will be included in all Nginx server block files:

```
sudo mkdir /etc/nginx/snippets
```

/etc/nginx/snippets/letsencrypt.conf

```nginx
location ^~ /.well-known/acme-challenge/ {
  allow all;
  root /var/lib/letsencrypt/;
  default_type "text/plain";
  try_files $uri =404;
}
```

Copy

/etc/nginx/snippets/ssl.conf

```nginx
ssl_dhparam /etc/ssl/certs/dhparam.pem;

ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 30s;

add_header Strict-Transport-Security "max-age=63072000" always;
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
```

Copy

The snippet above includes the chippers recommended by [Mozilla](https://mozilla.github.io/server-side-tls/ssl-config-generator/) , enables OCSP Stapling, HTTP Strict Transport Security (HSTS), and enforces few security‑focused HTTP headers.

Once the snippets are created, open the domain server block and include the `letsencrypt.conf` snippet, as shown below:

/etc/nginx/conf.d/example.com.conf

```nginx
server {
  listen 80;
  server_name example.com www.example.com;

  include snippets/letsencrypt.conf;
}
```

Copy

Reload the Nginx configuration for changes to take effect:

```
sudo systemctl reload nginx
```

Run the certbot tool with the webroot plugin to obtain the SSL certificate files for your domain:

```
sudo /usr/local/bin/certbot-auto certonly --agree-tos --email admin@example.com --webroot -w /var/lib/letsencrypt/ -d example.com -d www.example.com
```

If this the first time you invoke `certbot`, the tool will install the missing dependencies.

Once the SSL certificate is successfully obtained, certbot will print the following message:

```output
IMPORTANT NOTES:
 - Congratulations! Your certificate and chain have been saved at:
   /etc/letsencrypt/live/example.com/fullchain.pem
   Your key file has been saved at:
   /etc/letsencrypt/live/example.com/privkey.pem
   Your cert will expire on 2020-03-12. To obtain a new or tweaked
   version of this certificate in the future, simply run certbot-auto
   again. To non-interactively renew *all* of your certificates, run
   "certbot-auto renew"
 - If you like Certbot, please consider supporting our work by:

   Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
   Donating to EFF:                    https://eff.org/donate-le
```

Now that you have the certificate files, you can edit your [domain server block](https://linuxize.com/post/how-to-set-up-nginx-server-blocks-on-centos-8/) as follows:

/etc/nginx/conf.d/example.com.conf

```nginx
server {
    listen 80;
    server_name www.example.com example.com;

    include snippets/letsencrypt.conf;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name www.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    include snippets/ssl.conf;
    include snippets/letsencrypt.conf;

    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    include snippets/ssl.conf;
    include snippets/letsencrypt.conf;

    # . . . other code
}
```

Copy

With the configuration above we are [forcing HTTPS](https://linuxize.com/post/redirect-http-to-https-in-nginx/) and redirecting the www to non www version.

Finally, [reload the Nginx service](https://linuxize.com/post/nginx-commands-you-should-know/) for changes to take effect:

```
sudo systemctl reload nginx
```

Now, open your website using `https://`, and you’ll notice a green lock icon.

If you test your domain using the [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) , you’ll get an `A+` grade, as shown in the image below:

![SSLLABS Test](https://linuxize.com/post/secure-nginx-with-let-s-encrypt-on-centos-8/ssllabs-test_hud368b189ec9f420a1fcbc8264363661a_65757_768x0_resize_q75_lanczos.jpg)

## Auto-renewing Let’s Encrypt SSL certificate

Let’s Encrypt’s certificates are valid for 90 days. To automatically renew the certificates before they expire, [create a cronjob](https://linuxize.com/post/scheduling-cron-jobs-with-crontab/) that will run twice a day and automatically renew any certificate 30 days before expiration.

Use the `crontab` command to create a new cronjob:

```
sudo crontab -e
```

Paste the following line:

```sh
0 */12 * * * root test -x /usr/local/bin/certbot-auto -a \! -d /run/systemd/system && perl -e 'sleep int(rand(3600))' && /usr/local/bin/certbot-auto -q renew --renew-hook "systemctl reload nginx"
```

Copy

Save and close the file.

To test the renewal process, you can use the certbot command followed by the `--dry-run` switch:

```
sudo ./certbot-auto renew --dry-run
```

If there are no errors, it means that the test renewal process was successful.

## Conclusion

In this tutorial, we’ve shown you how to use the Let’s Encrypt client, certbot to download SSL certificates for your domain. We’ve also created Nginx snippets to avoid duplicating code and configured Nginx to use the certificates. At the end of the tutorial, we’ve set up a cronjob for automatic certificate renewal.

To learn more about Certbot, visit [their documentation](https://certbot.eff.org/docs/) page.


		--
		# References
		