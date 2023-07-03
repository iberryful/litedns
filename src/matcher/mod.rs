mod domain;
mod domain_keyword;
mod domain_suffix;
mod geosite;

use crate::configuration::RuleOpts;
pub use domain::DomainMatcher;
pub use domain_keyword::DomainKeywordMatcher;
pub use domain_suffix::DomainSuffixMatcher;
pub use geosite::GeoSiteMatcher;

pub trait Matcher {
    fn match_domain(&self, domain: &str) -> bool;
    fn resolver_name(&self) -> String;
    fn opts(&self) -> RuleOpts;
}

#[derive(Debug, Clone)]
pub struct MatchAllMatcher {
    remote: String,
    opts: RuleOpts,
}

impl Matcher for MatchAllMatcher {
    fn match_domain(&self, _domain: &str) -> bool {
        true
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }

    fn opts(&self) -> RuleOpts {
        self.opts.clone()
    }
}

impl MatchAllMatcher {
    pub fn new(remote: String, opts: RuleOpts) -> Self {
        Self { remote, opts }
    }
}
