use crate::configuration::Configuration;
use crate::router::Router;
use anyhow::{anyhow, Result};
use log::{debug, error, info};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::proto::op::{Header, ResponseCode};

use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

/// DNS Request Handler
#[derive(Clone)]
pub struct DNSRequestHandler {
    resolvers: HashMap<String, TokioAsyncResolver>,
    router: Arc<Mutex<Router>>,
}

impl DNSRequestHandler {
    pub fn new(conf: Configuration) -> Result<Self> {
        let resolvers: Result<HashMap<String, TokioAsyncResolver>> = conf
            .remotes
            .keys()
            .map(|name| {
                let mut opt = ResolverOpts::default();
                opt.cache_size = 0;
                let eg = conf
                    .remotes
                    .get(name.as_str())
                    .ok_or(anyhow!("remote {} not found", name.as_str()))?
                    .clone();
                let cfg = ResolverConfig::from_parts(None, vec![], eg);
                let resolver = AsyncResolver::tokio(cfg, opt)?;
                Ok((name.clone(), resolver))
            })
            .collect();
        let resolvers = resolvers?;
        let router = Router::try_from(conf)?;
        Ok(Self {
            resolvers,
            router: Arc::new(Mutex::new(router)),
        })
    }

    async fn handle_dns_request(&self, request: &Request) -> Result<Lookup> {
        let raw_query = request.query().name().to_string();
        let domain = raw_query
            .strip_suffix('.')
            .unwrap_or(raw_query.as_str())
            .to_string();
        let remote = self
            .router
            .lock()
            .await
            .route(domain.as_str())
            .ok_or(anyhow!("no route found for {}", domain))?;

        let resolver = self
            .resolvers
            .get(remote.as_str())
            .ok_or(anyhow!("resolver {} not found", remote))?;

        info!(
            "DNS Request {} {} is dispatched to -> {}",
            request.query().query_type().to_string(),
            domain,
            remote
        );

        let res = resolver
            .lookup(request.query().name(), request.query().query_type())
            .await?;
        Ok(res)
    }
}

#[async_trait::async_trait]
impl RequestHandler for DNSRequestHandler {
    async fn handle_request<R: ResponseHandler>(&self, request: &Request, r: R) -> ResponseInfo {
        debug!("New DNS Request: {:?}", request);

        let builder = MessageResponseBuilder::from_message_request(request);
        let header = Header::response_from_request(request.header());

        let response = self.handle_dns_request(request).await;
        if response.is_err() {
            let res = builder.error_msg(&header, ResponseCode::ServFail);
            return r.to_owned().send_response(res).await.unwrap_or_else(|e| {
                error!("Failed to send response: {:?}", e);
                header.into()
            });
        }

        let response = response.unwrap();
        let res = builder.build(header, response.record_iter(), &[], &[], &[]);

        return r.to_owned().send_response(res).await.unwrap_or_else(|e| {
            error!("Failed to send response: {:?}", e);
            header.into()
        });
    }
}
