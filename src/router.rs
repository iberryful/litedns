use crate::configuration::{Configuration, Rule};
use crate::geosite::{SiteGroup, SiteGroupList};
use crate::matcher::Matcher;
use crate::matcher::*;
use anyhow::{anyhow, Result};
use prost::Message;

use rust_embed::RustEmbed;

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

pub struct Router {
    matchers: Vec<Box<dyn Matcher + Send>>,
}

impl TryFrom<Configuration> for Router {
    type Error = anyhow::Error;

    fn try_from(conf: Configuration) -> std::result::Result<Self, Self::Error> {
        let mut matchers: Vec<Box<dyn Matcher + Send>> = Vec::new();
        let sites = load_geosite().unwrap();

        for rule in conf.rules.iter() {
            match rule {
                Rule::Domain { value, remote } => {
                    matchers.push(Box::new(DomainMatcher::new(value.clone(), remote.clone())));
                }
                Rule::DomainSuffix { value, remote } => {
                    matchers.push(Box::new(DomainSuffixMatcher::new(
                        value.clone(),
                        remote.clone(),
                    )));
                }
                Rule::DomainKeyword { value, remote } => {
                    matchers.push(Box::new(DomainKeywordMatcher::new(
                        value.clone(),
                        remote.clone(),
                    )));
                }
                Rule::GEOSITE { value, remote } => {
                    matchers.push(Box::new(GeoSiteMatcher::new(
                        get_sites(&sites, value.as_str())?,
                        remote.clone(),
                    )));
                }
                Rule::MATCH { remote } => {
                    matchers.push(Box::new(MatchAllMatcher::new(remote.clone())));
                }
            }
        }
        Ok(Self { matchers })
    }
}

impl Router {
    pub fn route(&self, domain: &str) -> Option<String> {
        for matcher in self.matchers.iter() {
            if matcher.match_domain(domain) {
                return Some(matcher.resolver_name());
            }
        }
        None
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
