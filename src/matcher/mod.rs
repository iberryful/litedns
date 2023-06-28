mod domain;
mod domain_keyword;
mod domain_suffix;
mod geosite;

pub use domain::DomainMatcher;
pub use domain_keyword::DomainKeywordMatcher;
pub use domain_suffix::DomainSuffixMatcher;
pub use geosite::GeoSiteMatcher;

pub trait Matcher {
    fn match_domain(&self, domain: &str) -> bool;
    fn resolver_name(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct MatchAllMatcher {
    remote: String,
}

impl Matcher for MatchAllMatcher {
    fn match_domain(&self, _domain: &str) -> bool {
        true
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }
}

impl MatchAllMatcher {
    pub fn new(remote: String) -> Self {
        Self { remote }
    }
}
