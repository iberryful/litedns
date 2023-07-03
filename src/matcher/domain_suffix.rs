use crate::configuration::RuleOpts;
use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct DomainSuffixMatcher {
    suffix: String,
    remote: String,
    opts: RuleOpts,
}

impl DomainSuffixMatcher {
    pub fn new(suffix: String, remote: String, opts: RuleOpts) -> Self {
        Self {
            suffix,
            remote,
            opts,
        }
    }
}

impl Matcher for DomainSuffixMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        domain.ends_with(&self.suffix)
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }

    fn opts(&self) -> RuleOpts {
        self.opts.clone()
    }
}
