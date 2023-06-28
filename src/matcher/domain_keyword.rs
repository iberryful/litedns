use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct DomainKeywordMatcher {
    keyword: String,
    remote: String,
}

impl DomainKeywordMatcher {
    pub fn new(keyword: String, remote: String) -> Self {
        Self { keyword, remote }
    }
}

impl Matcher for DomainKeywordMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        domain.contains(&self.keyword)
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }
}
