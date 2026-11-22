FROM rust:1.96-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY console ./console
COPY build.rs ./
COPY vendor ./vendor
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 util-linux && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home zntil
WORKDIR /app
COPY --from=builder /build/target/release/zntil /usr/local/bin/zntil
COPY config ./config
COPY entrypoint.sh /usr/local/bin/gateway-entrypoint
RUN chmod 755 /usr/local/bin/gateway-entrypoint
ENV ZNTIL_CONFIG=/app/config/railway.toml
EXPOSE 8080
ENTRYPOINT ["gateway-entrypoint"]
