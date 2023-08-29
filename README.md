# Litedns

Litedns is a lightweight DNS server written in Rust. It's design to be simple and easy to use especially for DNS request routing.

## Features
- [x] DNS request routing
- [x] support custom DNS servers with UDP, TCP, DoH, DoT protocols
- [x] support geosite
- [x] built-in DNS cache
- [x] built-in ipv6 setting
- [x] built with musl, no annoying glibc version issues
- [x] ipset support
- [x] socks5 proxy support

## Usage

Example configuration file can be found at [examples/config.yaml](examples/config.yaml).

```bash
litedns -c example/config.yaml
```

## Configuration

```yaml
server:
  listen: "0.0.0.0:8080"
log_level: debug

# supported protocols: udp, tcp, doh, dot
remotes:
  - name: 114
    uris:
      - udp://114.114.114.114:53
  - name: google
    uris:
      - doh://8.8.8.8?sni=dns.google
      - doh://8.8.4.4?sni=dns.google
    proxy: socks5://user:pass@localhost:1080

rules:
  - DOMAIN-SUFFIX, google.com, google || ipv6=disable
  - DOMAIN-KEYWORD, bing, google || ipv6=only
  - DOMAIN, baidu.com, 114 || ipv6=prefer
  - GEOSITE, NETFLIX, google || ipv6=defer&enable_https=true
  - GEOSITE, CN, 114, ipset4=cn&ipset6=cn6
  - MATCH, google
```

### route options
Additional options can be applied to routing rules using urlencode. Supported options are as follows:
- `ipv6`: `disable, only, prefer, defer, enable(default)`
- `ipset4`: `add resolved IPv4 addresses to specified ipset`
- `ipset6`: `add resolved IPv6 addresses to specified ipset`
- `enable_https`: `enable record type HTTPS(type 65), default is false`

### ipv6 setting
ipv6 setting can be applied to each routing rule after `||`, the additional setting are encoded in urlencoded format.
ipv6 setting can be one of the following values:
- enable: enable ipv6
- disable: disable ipv6, return `REFUSED` for AAAA request
- only: only use ipv6, return `REFUSED` for A request
- prefer: prefer ipv6, lookup A and AAAA request in parallel when A request is received, return AAAA record if it's available, otherwise return A record
- defer: defer ipv6, lookup A and AAAA request in parallel when AAAA request is received, return A record if it's available, otherwise return AAAA record

### geosite
Litedns embeds [geosite](https://github.com/Loyalsoldier/v2ray-rules-dat) database, it can be used to route DNS request based on client's location.
There is no need to download geosite database manually.

### proxy
Litedns support connecting to remote DNS server via proxy, currently only socks5 proxy is supported. 
Please be noted that UDP DNS is not supported by socks5 proxy

