# Build context is the repository root.
FROM rust:1-slim-trixie AS build
ARG CARGO_PROFILE=release
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --profile "$CARGO_PROFILE" --locked \
 && cp "target/$CARGO_PROFILE/dnsfilter" /dnsfilter

FROM debian:trixie-slim
COPY --from=build /dnsfilter /usr/local/bin/dnsfilter
ENTRYPOINT ["dnsfilter"]
