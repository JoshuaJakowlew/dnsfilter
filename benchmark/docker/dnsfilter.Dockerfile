# Build context is the repository root.
FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
COPY --from=build /src/target/release/dnsfilter /usr/local/bin/dnsfilter
ENTRYPOINT ["dnsfilter"]
