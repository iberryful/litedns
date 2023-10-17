use crate::configuration::{Configuration, Ipv6Setting, RuleOpts};
use crate::router::Router;
use anyhow::{anyhow, Result};
use log::{debug, error, info};

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::str::FromStr;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::proto::rr::Record;
use trust_dns_resolver::{AsyncResolver, Name};
use trust_dns_resolver::name_server::GenericConnector;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::proto::op::{Header, ResponseCode};
use trust_dns_server::proto::rr::RData;
use trust_dns_server::proto::rr::rdata::SOA;
use trust_dns_server::proto::rr::record_type::RecordType;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use crate::proxy_runtime::{ProxyConnector, TokioRuntimeProxyProvider};

/// DNS Request Handler
#[derive(Clone)]
pub struct DNSRequestHandler {
    resolvers: HashMap<String, AsyncResolver<GenericConnector<TokioRuntimeProxyProvider>>>,
    router: Router,
}

impl DNSRequestHandler {
    pub fn new(conf: Configuration) -> Result<Self> {
        let resolvers: Result<
            HashMap<String, AsyncResolver<GenericConnector<TokioRuntimeProxyProvider>>>,
        > = conf
            .remotes
            .keys()
            .map(|name| {
                let mut opt = ResolverOpts::default();
                opt.cache_size = 10000;
                opt.num_concurrent_reqs = 10;
                opt.timeout = std::time::Duration::from_secs(1);
                let eg = conf
                    .remotes
                    .get(name.as_str())
                    .ok_or(anyhow!("remote {} not found", name.as_str()))?
                    .clone();
                let cfg = ResolverConfig::from_parts(None, vec![], eg.clone());
                let runtime: ProxyConnector =
                    GenericConnector::new(TokioRuntimeProxyProvider::new(eg.proxy));
                let resolver = AsyncResolver::new(cfg, opt, runtime);
                Ok((name.clone(), resolver))
            })
            .collect();
        let resolvers = resolvers?;
        let router = Router::try_from(conf)?;

        Ok(Self { resolvers, router })
    }

    async fn handle_dns_request(&self, request: &Request) -> Result<(Vec<Record>, ResponseCode)> {
        let raw_query = request.query().name().to_string();
        let domain = raw_query
            .strip_suffix('.')
            .unwrap_or(raw_query.as_str())
            .to_string();
        let route = self
            .router
            .route(domain.as_str())
            .await
            .ok_or(anyhow!("no route found for {}", domain))?;

        let remote = route.remote.clone();
        let resolver = self
            .resolvers
            .get(remote.as_str())
            .ok_or(anyhow!("resolver {} not found", remote))?;

        if request.query().query_type() == RecordType::A && route.opts.ipv6 == Ipv6Setting::Only {
            return Ok((vec![], ResponseCode::NXDomain));
        }
        if request.query().query_type() == RecordType::AAAA
            && route.opts.ipv6 == Ipv6Setting::Disable
        {
            return Ok((vec![], ResponseCode::NXDomain));
        }
        if request.query().query_type() == RecordType::HTTPS && !route.opts.enable_https {
            return Ok((vec![], ResponseCode::Refused));
        }

        info!(
            "DNS Request {} {} is dispatched to -> {}",
            request.query().query_type().to_string(),
            domain,
            remote
        );

        let (records, code) = if request.query().query_type() == RecordType::AAAA
            && route.opts.ipv6 == Ipv6Setting::Defer
            || request.query().query_type() == RecordType::A
                && route.opts.ipv6 == Ipv6Setting::Prefer
        {
            dual_stack_resolve(request, resolver, &route.opts, domain).await
        } else {
            single_resolve(request, resolver).await?
        };
        records.iter().for_each(|record| {
            debug!("DNS Response: {:?}", record);
            #[cfg(target_os = "linux")]
            if let Err(err) = try_ipset_add(record, &route.opts) {
                error!("Failed to add ip to ipset: {:?}", err);
            }
        });
        Ok((records, code))
    }
}

#[cfg(target_os = "linux")]
fn try_ipset_add(record: &Record, opts: &RuleOpts) -> Result<()> {
    let mut ipset = None;
    if record.record_type() == RecordType::A && opts.ipset4.is_some() {
        ipset = opts.ipset4.clone();
    };
    if record.record_type() == RecordType::AAAA && opts.ipset6.is_some() {
        ipset = opts.ipset6.clone();
    }

    if let Some(ipset) = ipset {
        if let Some(rdata) = record.data() {
            if let Some(ip) = rdata.ip_addr() {
                let output = Command::new("ipset")
                    .arg("add")
                    .arg(ipset.clone())
                    .arg(ip.to_string())
                    .output()?;
                debug!("Added ip {} to ipset {}", ip, ipset.clone());
                if !output.status.success() {
                    let err = String::from_utf8_lossy(&output.stderr);
                    if err.contains("already added") {
                        return Ok(());
                    }
                    return Err(anyhow!("Failed to add ip to ipset: {}", err));
                }
            }
        }
    };

    Ok(())
}

#[async_trait::async_trait]
impl RequestHandler for DNSRequestHandler {
    async fn handle_request<R: ResponseHandler>(&self, request: &Request, r: R) -> ResponseInfo {
        debug!(
            "New DNS Request: {} {}",
            request.query().query_type(),
            request.query().name()
        );

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_recursion_available(true);

        match request.query().query_type() {
            RecordType::A | RecordType::AAAA | RecordType::HTTPS => {}
            _ => {
                let res = builder.error_msg(&header, ResponseCode::Refused);
                debug!(
                    "Unsupported query type: {}, {}",
                    request.query().query_type(),
                    request.query().name()
                );
                return r.to_owned().send_response(res).await.unwrap_or_else(|e| {
                    error!("Failed to send response: {:?}", e);
                    header.into()
                });
            }
        }

        let response = self.handle_dns_request(request).await;
        if response.is_err() {
            error!("Failed to handle request: {:?}", response);
            let res = builder.error_msg(&header, ResponseCode::ServFail);
            return r.to_owned().send_response(res).await.unwrap_or_else(|e| {
                error!("Failed to send response: {:?}", e);
                header.into()
            });
        }

        let (records, code) = response.unwrap();
        let mut soa: Vec<Record> = vec![];
        if records.is_empty() {
            debug!(
                "Send empty response for {} {}",
                request.query().query_type(),
                request.query().name()
            );
            soa.push(gen_soa());
            header.set_response_code(code);
        }
        let res = builder.build(header, records.iter(), &[], &soa, &[]);

        return r.to_owned().send_response(res).await.unwrap_or_else(|e| {
            error!("Failed to send response: {:?}", e);
            header.into()
        });
    }
}

fn gen_soa() -> Record {
    let name = Name::from_str(".").unwrap();
    let soa_rdata = SOA::new(
        Name::from_str("fake-ns.litedns.").unwrap(),
        Name::from_str("fake-hostmaster.litedns.").unwrap(),
        2023070501, // serial number
        3600,       // refresh
        3600,       // retry
        3600,       // expire
        60,         // minimum ttl
    );

    Record::from_rdata(name, 60, RData::SOA(soa_rdata))
}

async fn single_resolve(
    req: &Request,
    resolver: &AsyncResolver<ProxyConnector>,
) -> Result<(Vec<Record>, ResponseCode)> {
    let res = resolver
        .lookup(req.query().name(), req.query().query_type())
        .await;
    match res {
        Err(e) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => Ok((vec![], *response_code)),
            _ => Err(anyhow!(
                "failed to resolve {} {}: {}",
                req.query().query_type(),
                req.query().name(),
                e
            )),
        },
        Ok(lookup) => Ok((lookup.records().to_vec(), ResponseCode::NoError)),
    }
}

async fn dual_stack_resolve(
    req: &Request,
    resolver: &AsyncResolver<ProxyConnector>,
    opts: &RuleOpts,
    domain: String,
) -> (Vec<Record>, ResponseCode) {
    let (r1, r2) = tokio::join!(
        resolver.lookup(domain.as_str(), RecordType::A),
        resolver.lookup(domain.as_str(), RecordType::AAAA),
    );
    let (v4, v6) = (
        r1.map_or_else(|_| vec![], |l| l.records().to_vec()),
        r2.map_or_else(|_| vec![], |l| l.records().to_vec()),
    );

    let is_ipv6 = req.query().query_type() == RecordType::AAAA;
    let records: Vec<Record> = match opts.ipv6 {
        Ipv6Setting::Defer => {
            if !is_ipv6 {
                v4
            } else if v4.is_empty() {
                v6
            } else {
                vec![]
            }
        }
        Ipv6Setting::Prefer => {
            if is_ipv6 {
                v6
            } else if v6.is_empty() {
                v4
            } else {
                vec![]
            }
        }
        _ => {
            vec![]
        }
    };
    let code = if records.is_empty() {
        ResponseCode::NXDomain
    } else {
        ResponseCode::NoError
    };

    (records, code)
}
