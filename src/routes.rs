use crate::config;
use crate::httpbl;
use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use log::{error, info, warn};
use std::sync::Arc;

#[get("/check-ip")]
pub async fn check_ip(
    req: HttpRequest,
    httpbl_resolver: web::Data<Arc<httpbl::HttpblResolver>>,
    app_config: web::Data<Arc<config::Config>>,
) -> impl Responder {
    // Get the client IP from the configured header
    let client_ip_header_name = &app_config.client_ip_header;
    let client_ip_str = match req.headers().get(client_ip_header_name.to_lowercase()) {
        Some(ip_header) => match ip_header.to_str() {
            Ok(ip_str) => {
                // If header contains multiple IPs (e.g., X-Forwarded-For), take the first one
                ip_str.split(',').next().map(|s| s.trim())
            }
            Err(_) => {
                error!("Failed to parse {} header to string", client_ip_header_name);
                None
            }
        },
        None => {
            error!(
                "{} header not found in request from Nginx",
                client_ip_header_name
            );
            None
        }
    };

    let client_ip = match client_ip_str.and_then(|ip_str| ip_str.parse::<std::net::IpAddr>().ok()) {
        Some(ip) => ip,
        None => {
            // If IP is missing or unparseable, deny the request as we can't check http:BL
            warn!(
                "Invalid or missing client IP in header: {:?}",
                client_ip_str
            );
            return HttpResponse::Forbidden().body(format!(
                "Invalid or missing client IP header ({})",
                client_ip_header_name
            ));
        }
    };

    info!("Checking IP: {}", client_ip);

    // Perform http:BL lookup
    let lookup_result = httpbl_resolver.lookup(client_ip).await;
    info!(
        "http:BL lookup result for {}: {:?}",
        client_ip, lookup_result
    );

    // Apply policy
    let should_block = httpbl_resolver.apply_policy(&lookup_result, &app_config);

    if should_block {
        info!("Blocking IP: {} based on policy", client_ip);
        HttpResponse::Forbidden().body("Access denied.")
    } else {
        info!("Allowing IP: {} based on policy", client_ip);
        HttpResponse::Ok().body("Access allowed.")
    }
}
