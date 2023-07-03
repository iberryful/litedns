use crate::configuration::RuleOpts;
use crate::geosite::{domain, Domain, SiteGroup};
use crate::matcher::Matcher;
use regex::Regex;

#[derive(Clone, Debug)]
pub struct GeoSiteMatcher {
    site_group: SiteGroup,
    remote: String,
    opts: RuleOpts,
}

impl Matcher for GeoSiteMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        for site in self.site_group.domain.iter() {
            if self.geosite_match(domain, site) {
                return true;
            }
        }

        false
    }

    fn resolver_name(&self) -> String {
        self.remote.clone()
    }

    fn opts(&self) -> RuleOpts {
        self.opts.clone()
    }
}

impl GeoSiteMatcher {
    pub fn new(site_group: SiteGroup, remote: String, opts: RuleOpts) -> Self {
        Self {
            site_group,
            remote,
            opts,
        }
    }

    fn geosite_match(&self, domain: &str, site: &Domain) -> bool {
        match site.r#type() {
            domain::Type::Full => domain == site.value,
            domain::Type::Regex => {
                let res = Regex::new(site.value.as_str());
                match res {
                    Ok(re) => re.is_match(domain),
                    Err(_) => false,
                }
            }
            domain::Type::Domain => {
                if !domain.ends_with(site.value.as_str()) {
                    return false;
                }
                if domain.len() == site.value.len() {
                    return true;
                }
                let index = domain.len() - site.value.len();
                domain.as_bytes()[index - 1] == b'.'
            }
            domain::Type::Plain => domain.contains(site.value.as_str()),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::geosite::{domain, Domain, SiteGroup};
    use crate::matcher::{GeoSiteMatcher, Matcher};

    #[test]
    fn test_geosite_match() {
        let mut site_group = SiteGroup::default();

        let sites = [
            ("example.com", domain::Type::Full),
            ("keyword", domain::Type::Plain),
            (".a.com", domain::Type::Regex),
            ("qq.com", domain::Type::Domain),
        ];

        let cases = [
            ("example.com", true),
            ("example.com.cn", false),
            ("ba.com", true),
            ("a.com.cn", false),
            ("b.a.com", true),
            ("baa.q.qq.com", true),
            ("qq.com", true),
        ];

        for (value, r#type) in sites.iter() {
            let mut domain = Domain::default();
            domain.value = value.to_string();
            domain.r#type = *r#type as i32;
            site_group.domain.push(domain);
        }

        let matcher = GeoSiteMatcher {
            site_group: site_group.clone(),
            remote: "remote".to_string(),
            opts: Default::default(),
        };

        for (domain, expected) in cases.iter() {
            assert_eq!(
                matcher.match_domain(domain),
                *expected,
                "testing domain: {}",
                domain
            );
        }
    }
}
