use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct DomainSuffixMatcher {
    suffix: String,
    remote: String,
}

impl DomainSuffixMatcher {
    pub fn new(suffix: String, remote: String) -> Self {
        Self { suffix, remote }
    }
}

impl Matcher for DomainSuffixMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        domain.ends_with(&self.suffix)
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }
}
