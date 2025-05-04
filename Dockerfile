FROM rust:1.86 AS builder

WORKDIR /app
COPY . .

RUN cargo build --release --locked

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/httpbl-auth-service /app/httpbl-auth-service

EXPOSE 8080

ENTRYPOINT ["/app/httpbl-auth-service"]