|    IPv4 Addr    |        IPv6 Addr        |        ASn        |          Loc          |        Svc        |        Org        |
|:----------------|:------------------------|:------------------|:---------------------:|:-----------------:|:-----------------:|
| 8.8.8.8         | 2001:4860:4860::8888    | AS15169           | *Worldwide* (Anycast) | Google Public DNS | Google            |
| 8.8.4.4         | 2001:4860:4860::8844    | AS15169           | *Worldwide* (Anycast) | Google Public DNS | Google            |
| 77.88.8.8       | 2a02:6b8::feed:0ff      | AS13238           | *Worldwide* (Anycast) | Yandex.DNS        | Yandex            |
| 77.88.8.1       | 2a02:6b8:0:1::feed:0ff  | AS13238           | *Worldwide* (Anycast) | Yandex.DNS        | Yandex            |
| 1.1.1.1         | 2606:4700:4700::1111    | AS13335           | *Worldwide* (Anycast) | Cloudflare-DNS    | Cloudflare/APNIC  |
| 1.0.0.1         | 2606:4700:4700::1001    | AS13335           | *Worldwide* (Anycast) | Cloudflare-DNS    | Cloudflare/APNIC  |
| 1.1.1.3         | 2606:4700:4700::1113    | AS13335           | *Worldwide* (Anycast) | Cloudflare-DNS    | Cloudflare/APNIC  |
| 1.0.0.3         | 2606:4700:4700::1003    | AS13335           | *Worldwide* (Anycast) | Cloudflare-DNS    | Cloudflare/APNIC  |
| 9.9.9.9         | 2620:fe::fe             | AS19281           | *Worldwide* (Anycast) | Quad9 DNS         | PCH/IBM           |
| 9.9.9.10        | 2620:fe::10             | AS19281           | *Worldwide* (Anycast) | Quad9 DNS         | PCH/IBM           |
| 208.67.222.222  | 2620:119:35::35         | AS36692           | *Worldwide* (Anycast) | OpenDNS           | Cisco             |
| 208.67.220.220  | 2620:119:53::53         | AS36692           | *Worldwide* (Anycast) | OpenDNS           | Cisco             |
| 208.67.222.220  | 2620:0:ccc::2           | AS36692           | *Worldwide* (Anycast) | OpenDNS           | Cisco             |
| 208.67.220.222  | 2620:0:ccd::2           | AS36692           | *Worldwide* (Anycast) | OpenDNS           | Cisco             |
| 185.121.177.177 | 2a05:dfc7:5::53         | AS204136          | *Worldwide* (Anycast) | OpenNIC           | OpenNIC/Community |
| 169.239.202.202 | 2a05:dfc7:5::5353       | AS204136          | *Worldwide* (Anycast) | OpenNIC           | OpenNIC/Community |

## Google Public DNS [AS15169]:

8.8.8.8/2001:4860:4860::8888 (google-public-dns-a.google.com/dns.google)

8.8.4.4/2001:4860:4860::8844 (google-public-dns-b.google.com/dns.google)

DNS64:

2001:4860:4860::64 (google-public-dns64-a.google.com/dns64.dns.google)

2001:4860:4860::6464 (google-public-dns64-b.google.com/dns64.dns.google)

## Yandex.DNS [AS13238]:

77.88.8.8/2a02:6b8::feed:0ff (dns.yandex.ru)

77.88.8.1/2a02:6b8:0:1::feed:0ff (secondary.dns.yandex.ru)

## Cloudflare-DNS [AS13335]:

Cloudflare IPv4 DNS/Block malware:
1.1.1.1/2606:4700:4700::1111 (1dot1dot1dot1.cloudflare-dns.com or security.cloudflare-dns.com)

1.0.0.1/2606:4700:4700::1001 (1dot1dot1dot1.cloudflare-dns.com or security.cloudflare-dns.com)

## Cloudflare IPv4 DNS/Malware and Adult Content Blocking Together
1.1.1.3/2606:4700:4700::1113 (family.cloudflare-dns.com)
1.0.0.3/2606:4700:4700::1003 (family.cloudflare-dns.com)
### Test 1.1.1.1 for Families

After configuring 1.1.1.1 for Families, you can test if it is working as intended with the following URLs:

-   [https://malware.testcategory.com/](https://malware.testcategory.com/)

[](https://malware.testcategory.com/)-   [](https://malware.testcategory.com/): Use this to test if 1.1.1.1 for Families is blocking known malware addresses correctly.
-   [https://nudity.testcategory.com/](https://nudity.testcategory.com/)
[](https://nudity.testcategory.com/)[](https://nudity.testcategory.com/): Use this to test if 1.1.1.1 for Families is blocking known adult content and malware addresses correctly.

DNS64/Cloudflare IPv6 DNS:

2606:4700:4700::64 (dns64.cloudflare-dns.com)

2606:4700:4700::6400 (dns64.cloudflare-dns.com)

## Quad9 DNS [AS19281]:

9.9.9.9/2620:fe::fe (dns.quad9.net)

149.112.112.112/2620:fe::9

9.9.9.10/2620:fe::10 (dns-nosec.quad9.net)

149.112.112.10/2620:fe::fe:10

## OpenDNS [AS36692]:

208.67.222.222/2620:119:35::35 (resolver1.opendns.com)

208.67.220.220/2620:119:53::53 (resolver2.opendns.com)

208.67.222.220 (resolver3.opendns.com)

208.67.220.222 (resolver4.opendns.com)

2620:0:ccc::2 (resolver1.ipv6-sandbox.opendns.com)

2620:0:ccd::2 (resolver2.ipv6-sandbox.opendns.com)


## OpenNIC [AS204136]:

185.121.177.177/2a05:dfc7:5::53 (ns1.any.dns.opennic.glue)

169.239.202.202/2a05:dfc7:5::5353/2a05:dfc7:5353::53 (ns3.any.dns.opennic.glue/anyone.dnsrec.meo.ws)


## DNS.SB [AS6233]:

185.222.222.222/2a09:: (public-dns-a.dns.sb)

185.184.222.222/2a09::1 (public-dns-b.dns.sb)

## nextdns:

5.182.208.0/2a0d:2406:1801::

2a0d:2406:1802::


## Dyn (Oracle) [AS33517]:

216.146.35.35 (resolver1.dyndnsinternetguide.com)

216.146.36.36 (resolver2.dyndnsinternetguide.com)


## Verisign Public DNS [many Verisign ASn's]:

64.6.64.6/2620:74:1b::1:1 (recpubns1.nstld.net)

64.6.65.6/2620:74:1c::2:2 (recpubns2.nstld.net)

## Freenom World [AS60679]:

80.80.80.80

80.80.81.81


## Quad101 [AS131621]:

101.101.101.101/2001:de4::101 (twnic-public-dns.twnic.tw)

101.102.103.104/2001:de4::102 (twnic-public-dns.twnic.tw)

## 114DNS:

114.114.114.114 (public1.114dns.com)

114.114.115.115 (public2.114dns.com)

## sDNS [AS24151, AS24406, AS24409]:

1.2.4.8 (public1.sdns.cn)

210.2.4.8

## AliDNS [AS37963]:

223.5.5.5 (public1.alidns.com)

223.6.6.6 (public2.alidns.com)


## Level 3 DNS [AS3356]:

209.244.0.3 (resolver1.level3.net)

209.244.0.4 (resolver2.level3.net)

4.2.2.1 (a.resolvers.level3.net)

4.2.2.2 (b.resolvers.level3.net)

4.2.2.3 (c.resolvers.level3.net)

4.2.2.4 (d.resolvers.level3.net)

4.2.2.5 (e.resolvers.level3.net)

4.2.2.6 (f.resolvers.level3.net)

## Hurricane Electric [AS6939]:

74.82.42.42/2001:470:20::2 (ordns.he.net)


North America:

216.66.22.2/2001:470:0:90::2 (tserv2.ash1.he.net)

216.218.200.58 (tserv1.yyc1.he.net)

184.105.253.14/2001:470:0:6f::1 (tserv9.chi1.ipv6.he.net)

184.105.253.10/2001:470:0:7a::1 (tserv8.dal1.ipv6.he.net)

184.105.250.46/2001:470:0:24b::2 (tserv1.den1.he.net)

72.52.104.74/2001:470:0:45::2 (tserv1.fmt2.he.net)

64.62.134.130/2001:470:0:206::2 (tserv3.fmt1.he.net)

64.71.156.86 (tserv1.hnl1.he.net)

216.66.77.230/2001:470:0:24c::2 (tserv1.mci3.he.net)

66.220.18.42/2001:470:0:9d::2 (tserv1.lax1.he.net)

209.51.161.58/2001:470:0:8c::2 (tserv1.mia1.he.net)

209.51.161.14/2001:470:0:5d::2 (tserv1.nyc4.he.net)

66.220.7.82/2001:470:0:2b9::2 (tserv1.phx2.he.net)

216.218.226.238/2001:470:0:9b::2 (tserv1.sea1.he.net)

216.66.38.58/2001:470:0:c0::2 (tserv1.tor1.he.net)

184.105.255.26/2001:470:0:2b8::2 (tserv1.ywg1.he.net)

Europe:

216.66.84.46/2001:470:0:7d::2 (tserv1.ams1.he.net)

216.66.86.114/2001:470:0:220::2 (tserv1.ber1.he.net)

216.66.87.14/2001:470:0:2ba::2 (tserv1.bud1.he.net)

216.66.80.30/2001:470:0:69::2 (tserv1.fra1.he.net)

216.66.87.102 (tserv1.lis1.he.net)

216.66.80.26/2001:470:0:67::2 (tserv1.lon1.he.net)

216.66.88.98 (tserv1.lon2.he.net)

216.66.84.42/2001:470:0:7b::2 (tserv1.par1.he.net)

216.66.86.122/2001:470:0:221::2 (tserv1.prg1.he.net)

216.66.80.90/2001:470:0:11e::2 (tserv1.sto1.he.net)

216.66.80.162/2001:470:0:222::2 (tserv1.waw1.he.net)

216.66.80.98/2001:470:0:11d::2 (tserv1.zrh1.he.net)

Asia:

216.218.221.6/2001:470:0:ba::2 (tserv2.hkg1.he.net)

216.218.221.42/2001:470:0:17c::2 (tserv1.sin1.he.net)

74.82.46.6/2001:470:0:118::2 (tserv1.tyo1.he.net)

Africa:

216.66.87.98 (tserv1.jib1.he.net)

216.66.87.134 (tserv1.jnb1.he.net)

South America:

216.66.64.154 (tserv1.bog1.he.net)

Oceania:

216.218.142.50 (tserv1.syd1.he.net)

Middle East:

216.66.90.30 (tserv1.dxb1.he.net)

## Nippon Telegraph and Telephone (NTT) [AS2914]:

129.250.35.250/2001:418:3ff::53 (x.ns.gin.ntt.net)

129.250.35.251/2001:418:3ff::1:53 (y.ns.gin.ntt.net)


## MSK-IX DNS [AS8985]:

62.76.76.62/2001:6d0:6d0::2001 (dns.msk-ix.ru)

62.76.62.76/2001:6d0:d6::2001 (dns2.msk-ix.ru)

## TREX [AS29432]:

195.140.195.21/2001:67c:2b0::1 (dns.trex.fi)

195.140.195.22/2001:67c:2b0::2 (dns.trex.fi)

DNS64:

2001:67c:2b0::4 (dns64.trex.fi)

2001:67c:2b0::6 (dns64.trex.fi)



https://www.publicdns.xyz/

https://public-dns.info/

https://dns.sb/

https://www.nextdns.io/

https://quad9.net/faq/

https://tunnelbroker.net/status.php

http://www.trex.fi/service/resolvers.htm

http://www.trex.fi/2011/dns64.htm