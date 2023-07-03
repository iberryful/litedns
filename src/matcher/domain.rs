use crate::configuration::RuleOpts;
use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct DomainMatcher {
    domain: String,
    remote: String,
    opts: RuleOpts,
}

impl DomainMatcher {
    pub fn new(domain: String, remote: String, opts: RuleOpts) -> Self {
        Self {
            domain,
            remote,
            opts,
        }
    }
}

impl Matcher for DomainMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        domain == self.domain
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }

    fn opts(&self) -> RuleOpts {
        self.opts.clone()
    }
}
