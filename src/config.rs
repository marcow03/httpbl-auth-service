use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub access_key: String,
    pub bind_address: String,
    pub client_ip_header: String, // e.g., "x-real-ip"
    // Policy thresholds (example: block if threat score > 0 AND not a search engine)
    pub block_min_threat_score: u8,
    // http:BL type masks: 1=Suspicious, 2=Harvester, 4=Comment Spammer
    // Policy will block if (type_mask & block_type_mask) != 0
    pub block_type_mask: u8,
    // Set to true to allow search engines (type_mask == 0) regardless of threat
    pub allow_search_engines: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::Environment::with_prefix("HTTPBL"))
            .build()?;

        let config = config.try_deserialize::<Config>()?;
        Ok(config)
    }
}
