use anyhow::Result;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, name_server::GenericConnector};
use log::{error, info, warn};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub enum HttpblResult {
    NotListed,
    #[allow(dead_code)]
    SearchEngine(u8),
    Listed {
        #[allow(dead_code)]
        days: u8,
        threat: u8,
        type_mask: u8, // Bitmask: 1=Suspicious, 2=Harvester, 4=Comment Spammer
    },
    Error(String), // Error during lookup or parsing
}

#[derive(Clone)]
pub struct HttpblResolver {
    resolver: Resolver<GenericConnector<TokioRuntimeProvider>>,
    access_key: String,
}

impl HttpblResolver {
    pub async fn new(access_key: String) -> Result<Self> {
        // Use system configuration for DNS servers
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self {
            resolver,
            access_key,
        })
    }

    // Reverse the octets of an IPv4 address
    fn reverse_ipv4_octets(ip: &Ipv4Addr) -> String {
        let octets = ip.octets();
        format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
    }

    // Perform the http:BL lookup
    pub async fn lookup(&self, ip: IpAddr) -> HttpblResult {
        let ipv4 = match ip {
            IpAddr::V4(ipv4) => ipv4,
            // http:BL only supports IPv4 lookups
            IpAddr::V6(_) => {
                info!("Received IPv6 address, treating as not listed by http:BL");
                return HttpblResult::NotListed;
            }
        };

        let reversed_ip = Self::reverse_ipv4_octets(&ipv4);
        let query = format!("{}.{}.dnsbl.httpbl.org", self.access_key, reversed_ip);
        info!("Performing http:BL lookup for {}: {}", ip, query);

        match self.resolver.lookup_ip(query).await {
            Ok(lookup) => self.parse_response(lookup),
            Err(err) => {
                // NXDOMAIN (no results) is a specific error type in trust-dns
                if err.is_nx_domain() {
                    info!("Lookup result for {} is NXDOMAIN (Not Listed)", ip);
                    HttpblResult::NotListed
                } else {
                    error!("DNS resolution error for {}: {}", ip, err);
                    HttpblResult::Error(format!("DNS resolution failed: {}", err))
                }
            }
        }
    }

    // Parse the DNS A record response
    fn parse_response(&self, lookup_ip: LookupIp) -> HttpblResult {
        for ip in lookup_ip.iter() {
            if let IpAddr::V4(ipv4) = ip {
                let octets = ipv4.octets();
                // http:BL responses are always 127.D.T.Type
                if octets[0] == 127 {
                    info!("Received http:BL response: {}", ipv4);
                    let days = octets[1];
                    let threat = octets[2];
                    let type_mask = octets[3];

                    // Check for search engine (127.0.Serial.0)
                    if days == 0 && type_mask == 0 {
                        info!("Interpreted as Search Engine (Serial: {})", threat);
                        return HttpblResult::SearchEngine(threat); // Serial is in the threat octet for SE
                    } else {
                        info!(
                            "Interpreted as Listed: days={}, threat={}, type_mask={}",
                            days, threat, type_mask
                        );
                        return HttpblResult::Listed {
                            days,
                            threat,
                            type_mask,
                        };
                    }
                } else {
                    // This shouldn't happen based on http:BL spec, but log it
                    warn!("Received unexpected IP format from http:BL: {}", ipv4);
                    return HttpblResult::Error(format!("Unexpected IP format: {}", ipv4));
                }
            }
        }

        warn!("DNS lookup succeeded but no A records found.");
        HttpblResult::Error("No A records found".to_string())
    }

    // Apply the blocking policy
    pub fn apply_policy(&self, result: &HttpblResult, policy: &crate::config::Config) -> bool {
        match result {
            HttpblResult::NotListed => {
                info!("Policy: Not listed -> Allow");
                false // Not listed, do not block
            }
            HttpblResult::SearchEngine(_) => {
                if policy.allow_search_engines {
                    info!("Policy: Search engine -> Allow (configured)");
                    false // Allow search engines if configured
                } else {
                    info!("Policy: Search engine -> Block (configured)");
                    true // Block search engines if configured not to allow
                }
            }
            HttpblResult::Listed {
                days: _,
                threat,
                type_mask,
            } => {
                let block_by_threat = *threat >= policy.block_min_threat_score;
                let block_by_type = (*type_mask & policy.block_type_mask) != 0;

                if block_by_threat || block_by_type {
                    info!(
                        "Policy: Listed (threat={}, type_mask={}) -> Block (Matches policy: min_threat={}, block_type_mask={})",
                        threat, type_mask, policy.block_min_threat_score, policy.block_type_mask
                    );
                    true // Block if policy matches
                } else {
                    info!(
                        "Policy: Listed (threat={}, type_mask={}) -> Allow (Does not match policy: min_threat={}, block_type_mask={})",
                        threat, type_mask, policy.block_min_threat_score, policy.block_type_mask
                    );
                    false // Listed but policy doesn't require blocking
                }
            }
            HttpblResult::Error(err) => {
                error!(
                    "Policy: Error during lookup ({}) -> Defaulting to Allow",
                    err
                );
                // Decide how to handle errors - usually allow to avoid blocking legitimate users
                // during temporary lookup failures.
                false // Allow by default on error
            }
        }
    }
}
