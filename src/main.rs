use actix_web::{App, HttpServer, web};
use anyhow::{Context, Result};
use httpbl::HttpblResolver;
use log::info;
use std::sync::Arc;

mod config;
mod httpbl;
mod routes;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let config = Arc::new(config::Config::from_env()?);
    info!("Configuration loaded: {:?}", config);

    // Initialize http:BL resolver
    let httpbl_resolver = Arc::new(
        HttpblResolver::new(config.access_key.clone())
            .await
            .context("Failed to initialize http:BL resolver")?,
    );
    info!("http:BL resolver initialized.");

    info!("Starting http:BL server on {}", config.bind_address);

    let config_clone = config.clone();
    Ok(HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(httpbl_resolver.clone()))
            .app_data(web::Data::new(config_clone.clone()))
            .service(routes::check_ip)
    })
    .bind(config.bind_address.clone())?
    .run()
    .await?)
}
