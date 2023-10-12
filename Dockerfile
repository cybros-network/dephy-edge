FROM rust:bookworm AS builder
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
  build-essential \
  protobuf-compiler \
  llvm \
  clang \
  libclang-dev \
  libssl-dev \
  git-core \
  pkg-config \
  && apt-get clean \
  && rm -rf /tmp/* /var/tmp/*

WORKDIR /builder
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release

FROM debian:bookworm-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
  libssl-dev iproute2 \
  ca-certificates \
  && apt-get clean \
  && rm -rf /tmp/* /var/tmp/*

WORKDIR /app
COPY --from=builder /builder/rumqttd.toml /app/rumqttd.default.toml
COPY --from=builder /builder/target/release/dephy-edge .
COPY --from=builder /builder/target/release/dephy-edge-utils .

ENV RUST_LOG=dephy_edge=info,rumqttd::*=off
ENV MQTT_CONFIG_FILE=/app/rumqttd.default.toml
ENV HTTP_BIND_ADDRESS=[::]:3883

LABEL org.opencontainers.image.source https://github.com/dephy-io/dephy-edge

CMD /app/dephy-edge
