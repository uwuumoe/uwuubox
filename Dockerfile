FROM rust:1-slim-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY migrations ./migrations
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/uwuubox /usr/local/bin/uwuubox
COPY static ./static
# `sqlx::migrate!` embeds migrations in the binary: it migrates on boot,
# then serves. No separate migration step.
EXPOSE 3000
CMD ["uwuubox"]
