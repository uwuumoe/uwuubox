FROM rust:1-slim-bookworm AS build
# reqwest (via otlp reqwest-blocking-client) links native-tls/OpenSSL.
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
# Askama compiles templates into the binary: needed at build time only.
COPY templates ./templates
RUN cargo build --release
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/uwuubox /usr/local/bin/uwuubox
COPY static ./static
# `sqlx::migrate!` embeds migrations in the binary: it migrates on boot,
# then serves. No separate migration step.
EXPOSE 3000
CMD ["uwuubox"]
