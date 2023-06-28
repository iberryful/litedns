use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct DomainMatcher {
    domain: String,
    remote: String,
}

impl DomainMatcher {
    pub fn new(domain: String, remote: String) -> Self {
        Self { domain, remote }
    }
}

impl Matcher for DomainMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        domain == self.domain
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }
}
