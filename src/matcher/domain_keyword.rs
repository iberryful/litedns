use crate::configuration::RuleOpts;
use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct DomainKeywordMatcher {
    keyword: String,
    remote: String,
    opts: RuleOpts,
}

impl DomainKeywordMatcher {
    pub fn new(keyword: String, remote: String, opts: RuleOpts) -> Self {
        Self {
            keyword,
            remote,
            opts,
        }
    }
}

impl Matcher for DomainKeywordMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        domain.contains(&self.keyword)
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }

    fn opts(&self) -> RuleOpts {
        self.opts.clone()
    }
}
