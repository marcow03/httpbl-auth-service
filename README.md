# httpbl-auth-service

A proxy service designed to integrate [Project Honey Pot's Http:BL](https://www.projecthoneypot.org/httpbl.php) with Nginx using the `auth_request` module. Written in Rust for performance and reliability.

> [!WARNING]
> This is work in progress... It's **NOT production-ready**, **untested** and intended for **hobby use**.

## What is Http:BL?

[Project Honey Pot](https://www.projecthoneypot.org/) is a distributed network of honeypots that capture information about bots and crawlers on the internet, specifically focusing on those that harvest email addresses or engage in spamming behavior.

**Http:BL** is a service provided by Project Honey Pot that allows website administrators to identify and block or restrict access from known malicious bots based on IP address. It works like a DNS-based blacklist (DNSBL), but for web traffic. This service performs a DNS lookup on a visitor's IP address against `dnsbl.httpbl.org` and returns a result indicating if the IP is listed, its threat level, type (harvester, spammer, suspicious), and how recently it was seen.

This `httpbl-auth-service` acts as an intermediary, performing the Http:BL DNS lookup for incoming web requests and informing Nginx whether to allow or deny access based on a configurable policy.

## Features

- Performs Http:BL DNS lookups for IPv4 addresses.
- Parses the Http:BL DNS response (days, threat score, type mask).
- Applies a configurable policy to determine if an IP should be blocked.
- Provides a simple HTTP endpoint for integration with Nginx `auth_request`.
- Built in Rust for efficiency.

## How it Works

1. An HTTP request arrives at Nginx.
2. Nginx, configured with `auth_request`, sends a subrequest to the `httpbl-auth-service` endpoint, passing the client's IP in a header.
3. The `httpbl-auth-service` receives the IP, performs the Http:BL DNS lookup using your Access Key, and interprets the result.
4. Based on the lookup result and its internal policy, the service returns an HTTP status code to Nginx (e.g., `200 OK` to allow, `403 Forbidden` to deny).
5. Nginx receives the status code and enforces the access policy (allows or denies the original client request).

## Configuration

The service is configured via environment variables:

| Environment Variable         | Description                                                                                                                         | Example        |
| :--------------------------- | :---------------------------------------------------------------------------------------------------------------------------------- | :------------- |
| `HTTPBL_ACCESS_KEY`             | Your 12-character Http:BL access key from Project Honey Pot.                                                                        | `j0L5sNQVjEzYmh356`           |
| `HTTPBL_BIND_ADDRESS`           | The IP address and port the service should bind to.                                                                                 | `0.0.0.0:8080` |
| `HTTPBL_CLIENT_IP_HEADER`       | The name of the HTTP header Nginx will use to pass the client's IP address (e.g., `X-Real-Ip`).                                     | `X-Real-Ip`    |
| `HTTPBL_BLOCK_MIN_THREAT_SCORE` | Minimum Http:BL threat score (0-255) to consider blocking an IP.                                                                    | `0`            |
| `HTTPBL_BLOCK_TYPE_MASK`        | A bitmask of Http:BL types to block. Sum of values: 1=Suspicious, 2=Harvester, 4=Comment Spammer. E.g., `7` blocks all three.       | `0`            |
| `HTTPBL_ALLOW_SEARCH_ENGINES`   | Set to `true` or `false`. If `true`, known search engines (Type 0) will always be allowed, regardless of threat score or type mask. | `true`         |

**Example Policy:** To block IPs with a threat score of 50 or higher, OR any IP identified as a Harvester (Type 2) or Comment Spammer (Type 4), while still allowing known search engines:
`HTTPBL_BLOCK_MIN_THREAT_SCORE=50`
`HTTPBL_BLOCK_TYPE_MASK=6` (2 + 4)
`HTTPBL_ALLOW_SEARCH_ENGINES=true`

## Installation

### Via Docker (Recommended)

The easiest way to deploy the service is using the pre-built Docker image available on GitHub Container Registry.

1. **Pull the image:**

    ```bash
    docker pull ghcr.io/marcow03/httpbl-auth-service:latest
    ```

2. **Run the container:**

    ```bash
    docker run -d \
      --name httpbl-auth-service \
      -e HTTPBL_ACCESS_KEY=your_access_key \
      -e HTTPBL_BIND_ADDRESS=0.0.0.0:8080 \
      -e HTTPBL_CLIENT_IP_HEADER=X-Real-Ip \
      -e HTTPBL_BLOCK_MIN_THREAT_SCORE=1 \
      -e HTTPBL_BLOCK_TYPE_MASK=7 \
      -e HTTPBL_ALLOW_SEARCH_ENGINES=true \
      ghcr.io/marcow03/httpbl-auth-service:latest
    ```

    Replace `your_access_key` and adjust other environment variables according to your desired configuration.

3. **Using Docker Compose:**
    For easier management, you can use Docker Compose. Create a `docker-compose.yml` file:

    ```yaml
    version: "3.8"
    services:
      httpbl-auth-service:
        image: ghcr.io/marcow03/httpbl-auth-service:latest
        container_name: httpbl-auth-service
        restart: unless-stopped
        environment:
          HTTPBL_ACCESS_KEY: your_access_key
          HTTPBL_BIND_ADDRESS: 0.0.0.0:8080
          HTTPBL_CLIENT_IP_HEADER: X-Real-Ip
          HTTPBL_BLOCK_MIN_THREAT_SCORE: 1
          HTTPBL_BLOCK_TYPE_MASK: 7
          HTTPBL_ALLOW_SEARCH_ENGINES: true
        # If Nginx is on a different host, uncomment and map a port
        # ports:
        #   - "8080:8080"
        # Ensure Nginx can access this container on the Docker network
        networks:
          - your_nginx_network # Replace with the Docker network your Nginx/NPM uses

    # Define external network if Nginx/NPM is on one
    networks:
      your_nginx_network: # Replace with the actual network name
        external: true
    ```

    Run `docker compose up -d`. Remember to replace placeholders and ensure this service is on the same Docker network as your Nginx Proxy Manager container so they can communicate directly by container name (`httpbl-auth-service:8080`).

### Building from Source

If you prefer to build the service yourself, follow these steps:

1. **Install Rust:** If you don't have Rust installed, follow the instructions on the [official Rust website](https://www.rust-lang.org/tools/install).
2. **Clone the repository:**

    ```bash
    git clone https://github.com/marcow03/httpbl-auth-service.git
    cd httpbl-auth-service
    ```

3. **Build the release binary:**

    ```bash
    cargo build --release
    ```

4. **Run the binary:**
    The executable will be located in the `target/release/` directory. Run it by setting the environment variables before the command:

    ```bash
    HTTPBL_ACCESS_KEY=your_access_key \
    HTTPBL_BIND_ADDRESS=127.0.0.1:8080 \
    HTTPBL_CLIENT_IP_HEADER=X-Real-Ip \
    HTTPBL_BLOCK_MIN_THREAT_SCORE=1 \
    HTTPBL_BLOCK_TYPE_MASK=7 \
    HTTPBL_ALLOW_SEARCH_ENGINES=true \
    ./target/release/httpbl-auth-service
    ```

    Adjust environment variables and the path to the executable as needed.

## Usage (Nginx Integration)

To use the service with Nginx (including Nginx Proxy Manager), configure Nginx to use the `auth_request` module to call your `httpbl-auth-service`.

In Nginx Proxy Manager, navigate to the specific Proxy Host configuration, go to the **Advanced** tab, and add the following `Nginx Configuration` snippet. Replace `http://httpbl-auth-service:8080` with the correct address and port of your running service (e.g., `http://localhost:8080` if running directly on the host, or `http://<container_name>:8080` if using Docker Compose on the same network).

```nginx
# Pass the real client IP to the auth service in a header.
# Make sure this header name matches APP_CLIENT_IP_HEADER configuration.
proxy_set_header X-Real-IP $remote_addr;
# Or use X-Forwarded-For if Nginx is behind another proxy:
# proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;


# Define an internal location for the auth request subrequest.
# 'internal' prevents direct access to this location from outside.
location /_httpbl_auth {
    internal;
    # proxy_pass points to your running httpbl-auth-service
    proxy_pass http://httpbl-auth-service:8080/check-ip; # !!! REPLACE with your service address and port !!!

    # Pass original request details if needed by the auth service (optional)
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    # Pass the client IP again if using X-Forwarded-For above
    # proxy_set_header X-Real-IP $remote_addr;
}

# Use the auth_request directive in the main location block (e.g., '/')
# This tells Nginx to perform a subrequest to /_httpbl_auth before processing the main request.
auth_request /_httpbl_auth;

# Optional: Customize the response for blocked requests (403 Forbidden)
# error_page 403 = /custom_403_page.html; # Serve a custom HTML page
# error_page 403 = @handle_blocked; # Redirect to a named location for logging/handling
# location @handle_blocked { return 403; }
```

## Available HTTP Routes

The service exposes the following endpoint:

**`GET /check-ip`**

- **Description:** Performs an Http:BL lookup for the IP address provided in the header specified by `HTTPBL_CLIENT_IP_HEADER`. Applies the configured blocking policy.
- **Request:** A `GET` request with the client IP in the configured header (e.g., `X-Real-Ip`).
- **Response:**
  - `200 OK`: The IP is allowed based on the current policy.
  - `403 Forbidden`: The IP is blocked based on the current policy (e.g., listed with high threat or matched block types).
