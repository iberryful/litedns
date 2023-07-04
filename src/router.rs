use crate::configuration::{Configuration, Rule, RuleOpts};
use crate::geosite::{SiteGroup, SiteGroupList};
use crate::matcher::Matcher;
use crate::matcher::*;
use anyhow::{anyhow, Result};
use prost::Message;
use rust_embed::RustEmbed;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(RustEmbed)]
#[folder = "deps/"]
struct Asset;

pub fn load_geosite() -> Result<SiteGroupList> {
    let mut geosite = SiteGroupList::default();
    let asset = Asset::get("geosite.dat").ok_or(anyhow!("missing geosite.dat"))?;
    let buf = asset.data.to_vec();
    geosite.merge(&*buf)?;
    Ok(geosite)
}

#[derive(Clone)]
pub struct Router {
    matchers: Arc<Vec<Box<dyn Matcher + Sync + Send + 'static>>>,
    cache: Arc<RwLock<HashMap<String, usize>>>,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub remote: String,
    pub opts: RuleOpts,
}

impl TryFrom<Configuration> for Router {
    type Error = anyhow::Error;

    fn try_from(conf: Configuration) -> std::result::Result<Self, Self::Error> {
        let mut matchers: Vec<Box<dyn Matcher + Send + Sync + 'static>> = vec![];
        let sites = load_geosite().unwrap();

        for rule in conf.rules.iter() {
            match rule {
                Rule::Domain {
                    value,
                    remote,
                    opts,
                } => {
                    matchers.push(Box::new(DomainMatcher::new(
                        value.clone(),
                        remote.clone(),
                        opts.clone(),
                    )));
                }
                Rule::DomainSuffix {
                    value,
                    remote,
                    opts,
                } => {
                    matchers.push(Box::new(DomainSuffixMatcher::new(
                        value.clone(),
                        remote.clone(),
                        opts.clone(),
                    )));
                }
                Rule::DomainKeyword {
                    value,
                    remote,
                    opts,
                } => {
                    matchers.push(Box::new(DomainKeywordMatcher::new(
                        value.clone(),
                        remote.clone(),
                        opts.clone(),
                    )));
                }
                Rule::GeoSite {
                    value,
                    remote,
                    opts,
                } => {
                    matchers.push(Box::new(GeoSiteMatcher::new(
                        get_sites(&sites, value.as_str())?,
                        remote.clone(),
                        opts.clone(),
                    )));
                }
                Rule::Match { remote, opts } => {
                    matchers.push(Box::new(MatchAllMatcher::new(remote.clone(), opts.clone())));
                }
            }
        }
        Ok(Self {
            matchers: Arc::new(matchers),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

impl Router {
    pub async fn route(&self, domain: &str) -> Option<Route> {
        let mut index = self.cache.read().await.get(domain).map(|x| x.to_owned());

        if index.is_none() {
            for (idx, matcher) in self.matchers.iter().enumerate() {
                if matcher.match_domain(domain) {
                    self.cache
                        .write()
                        .await
                        .borrow_mut()
                        .insert(domain.to_owned(), idx);
                    index = Some(idx);
                    break;
                }
            }
        }
        index
            .and_then(|i| self.matchers.get(i))
            .map(|matcher| Route {
                remote: matcher.resolver_name(),
                opts: matcher.opts(),
            })
    }
}

fn get_sites(list: &SiteGroupList, keyword: &str) -> Result<SiteGroup> {
    for group in list.site_group.iter() {
        if group.tag == keyword {
            return Ok(group.clone());
        }
    }
    Err(anyhow!("geosite {} not found", keyword))
}
