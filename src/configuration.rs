use anyhow::{anyhow, Result};
use config::Config;

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol as DnsProtocol,
};
use url::Url;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    DOT,
    DOH,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub struct Endpoint {
    pub protocol: Protocol,
    pub host: IpAddr,
    pub port: u16,
    pub sni: Option<String>,
    pub verify: bool,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct EndpointGroup {
    pub name: String,
    #[serde(alias = "uris")]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub enum Rule {
    Domain { value: String, remote: String },
    DomainSuffix { value: String, remote: String },
    DomainKeyword { value: String, remote: String },
    GEOSITE { value: String, remote: String },
    MATCH { remote: String },
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Configuration {
    pub server: ServerConfig,
    #[serde(deserialize_with = "deserialize_remotes")]
    pub remotes: HashMap<String, EndpointGroup>,
    pub rules: Vec<Rule>,
}

impl Configuration {
    pub fn parse(path: PathBuf) -> Result<Self> {
        let conf = Config::builder()
            .add_source(config::File::from(path))
            .build()?;
        conf.try_deserialize().map_err(|e| e.into())
    }
}

impl TryFrom<&str> for Protocol {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        match s {
            "tcp" => Ok(Protocol::TCP),
            "udp" => Ok(Protocol::UDP),
            "dot" => Ok(Protocol::DOT),
            "doh" => Ok(Protocol::DOH),
            _ => Err(anyhow::anyhow!("Invalid protocol: {}", s)),
        }
    }
}

impl From<Protocol> for DnsProtocol {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::TCP => DnsProtocol::Tcp,
            Protocol::UDP => DnsProtocol::Udp,
            Protocol::DOT => DnsProtocol::Tls,
            Protocol::DOH => DnsProtocol::Https,
        }
    }
}

impl TryFrom<&str> for Endpoint {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let url = Url::parse(s)?;
        let protocol: Protocol = url.scheme().try_into()?;
        let queries: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let verify = queries.get("verify").map(|v| v == "true").unwrap_or(false);
        let port = url.port().unwrap_or(protocol.default_port());
        let host = url.host_str().ok_or(anyhow!("missing host"))?;

        Ok(Endpoint {
            protocol,
            host: IpAddr::from_str(host)?,
            port,
            sni: queries.get("sni").cloned(),
            verify,
            path: url.path().to_string(),
        })
    }
}

impl TryFrom<String> for Endpoint {
    type Error = anyhow::Error;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl From<EndpointGroup> for NameServerConfigGroup {
    fn from(eg: EndpointGroup) -> Self {
        let mut group = NameServerConfigGroup::new();
        for endpoint in eg.endpoints {
            let config = NameServerConfig::from(endpoint);
            group.push(config);
        }
        group
    }
}

impl From<Endpoint> for NameServerConfig {
    fn from(e: Endpoint) -> Self {
        let mut config = NameServerConfig::new((e.host, e.port).into(), e.protocol.into());
        config.tls_dns_name = e.sni;
        config
    }
}

impl TryFrom<&str> for Rule {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let mut parts = s
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(String::from);

        let rule_type = parts.next().ok_or(anyhow!("missing rule type"))?;
        let value = parts.next().ok_or(anyhow!("missing rule value"))?;
        match rule_type.as_str() {
            "DOMAIN" => Ok(Rule::Domain {
                value,
                remote: parts.next().ok_or(anyhow!("missing remote"))?,
            }),
            "DOMAIN-SUFFIX" => Ok(Rule::DomainSuffix {
                value,
                remote: parts.next().ok_or(anyhow!("missing remote"))?,
            }),
            "DOMAIN-KEYWORD" => Ok(Rule::DomainKeyword {
                value,
                remote: parts.next().ok_or(anyhow!("missing remote"))?,
            }),
            "GEOSITE" => Ok(Rule::GEOSITE {
                value,
                remote: parts.next().ok_or(anyhow!("missing remote"))?,
            }),
            "MATCH" => Ok(Rule::MATCH {
                remote: value,
            }),
            _ => Err(anyhow!("invalid rule type: {}", rule_type)),
        }
    }
}

impl TryFrom<String> for Rule {
    type Error = anyhow::Error;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl Protocol {
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::TCP => 53,
            Protocol::UDP => 53,
            Protocol::DOT => 853,
            Protocol::DOH => 443,
        }
    }
}

pub fn deserialize_remotes<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, EndpointGroup>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<EndpointGroup> = Vec::deserialize(deserializer)?;
    v.into_iter()
        .map(|eg| Ok((eg.name.to_string(), eg)))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::configuration::{Configuration, Endpoint, Protocol, Rule};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    #[test]
    fn test_parse() {
        let conf = Configuration::parse(PathBuf::from("tests/config/config.yaml"));
        println!("{:?}", conf);
        assert!(conf.is_ok());
    }

    #[test]
    fn test_parse_endpoint_ok() {
        let uri = "doh://1.1.1.1/resolve?verify=true&sni=cloudflare-dns.com".to_string();
        let endpoint = Endpoint::try_from(uri);
        assert!(endpoint.is_ok());
        assert_eq!(
            endpoint.unwrap(),
            Endpoint {
                protocol: Protocol::DOH,
                host: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 443,
                sni: Some("cloudflare-dns.com".to_string()),
                verify: true,
                path: "/resolve".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_endpoint_err() {
        let uri = "quic://1.1.1.1/resolve?verify=true&sni=cloudflare-dns.com";
        let endpoint = Endpoint::try_from(uri);
        assert_eq!(endpoint.is_err(), true);
    }

    #[test]
    fn test_parse_rule_ok() {
        let cases = vec![
            (
                "DOMAIN,google.com,google",
                Ok(Rule::Domain {
                    value: "google.com".to_string(),
                    remote: "google".to_string(),
                }),
            ),
            (
                "DOMAIN-SUFFIX,google.com,google",
                Ok(Rule::DomainSuffix {
                    value: "google.com".to_string(),
                    remote: "google".to_string(),
                }),
            ),
            (
                "DOMAIN-KEYWORD,google.com,google",
                Ok(Rule::DomainKeyword {
                    value: "google.com".to_string(),
                    remote: "google".to_string(),
                }),
            ),
            (
                "GEOSITE,CN,google",
                Ok(Rule::GEOSITE {
                    value: "CN".to_string(),
                    remote: "google".to_string(),
                }),
            ),
            (
                "MATCH,google",
                Ok(Rule::MATCH {
                    remote: "google".to_string(),
                }),
            ),
            ("MATCH", Err(())),
            ("GEOIP, 114.114.114.114", Err(())),
        ];

        for (input, expect) in cases {
            let rule = Rule::try_from(input);
            if expect.is_ok() {
                assert_eq!(rule.is_ok(), true);
                assert_eq!(rule.unwrap(), expect.unwrap());
            } else {
                assert_eq!(rule.is_err(), true);
            }
        }
    }
}
