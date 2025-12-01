# Build stage
FROM rust:1.90 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libclang-dev \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install SP1
#RUN curl -L https://sp1.succinct.xyz | bash && \
#    ~/.sp1/bin/sp1up && \
#    ~/.sp1/bin/cargo-prove prove --version

COPY rust-toolchain.toml .

RUN rustc --version

# Copy only what's needed for the build
COPY --exclude=.git --exclude=target --exclude=tests . .

# Build the server
RUN --mount=type=ssh \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --bin proposer --release && \
    cp target/release/proposer /build/proposer

RUN --mount=type=ssh \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --bin challenger --release && \
    cp target/release/challenger /build/challenger

RUN --mount=type=ssh \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --bin fetch-fault-dispute-game-config --release && \
    cp target/release/fetch-fault-dispute-game-config /build/fetch-fault-dispute-game-config


# Final stage
FROM rust:1.90-slim

WORKDIR /app

# Install required runtime dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy SP1
#COPY --from=builder ~/.sp1 ~/.sp1

# Copy only the built binaries from builder
COPY --from=builder /build/proposer /usr/local/bin/proposer
COPY --from=builder /build/challenger /usr/local/bin/challenger
COPY --from=builder /build/fetch-fault-dispute-game-config /usr/local/bin/fetch-fault-dispute-game-config
