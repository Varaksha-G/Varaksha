# ════════════════════════════════════════════════════════════════════════════════
# Varaksha Risk-Cache Gateway — Multi-stage Docker Build
# Stage 1: Compile Rust binary  (no ONNX Runtime needed at compile time;
#           ort crate uses load-dynamic feature)
# Stage 2: Slim runtime with libonnxruntime.so + model artefacts
# ════════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pre-cache dependencies (layer cache: only rebuild when Cargo files change)
COPY risk-cache/Cargo.toml risk-cache/Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release 2>/dev/null; \
    rm -f target/release/risk-cache target/release/.fingerprint/risk-cache* 2>/dev/null; true

# Compile actual source
COPY risk-cache/src ./src
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libssl3 ca-certificates curl libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Download ONNX Runtime shared library (ort crate load-dynamic feature resolves at runtime)
ARG ORT_VERSION=1.20.1
RUN curl -fsSL \
    "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-${ORT_VERSION}.tgz" \
    -o /tmp/ort.tgz \
    && tar -xzf /tmp/ort.tgz -C /tmp \
    && cp /tmp/onnxruntime-linux-x64-${ORT_VERSION}/lib/libonnxruntime*.so* /usr/local/lib/ \
    && ln -sf /usr/local/lib/libonnxruntime.so.${ORT_VERSION} /usr/local/lib/libonnxruntime.so \
    && ldconfig \
    && rm -rf /tmp/ort.tgz "/tmp/onnxruntime-linux-x64-${ORT_VERSION}"

# Copy compiled gateway binary
COPY --from=builder /build/target/release/risk-cache /app/risk-cache

# Copy model artefacts (Railway: override with volume mount in production)
COPY models/ /app/models/

# Directories for logs and optimized model cache
RUN mkdir -p /app/logs /app/models/optimized

# ── Environment defaults ──────────────────────────────────────────────────────
# Override via Railway environment variables or docker-compose env_file
ENV RUST_LOG=info
ENV VARAKSHA_MODELS_DIR=/app/models
ENV VARAKSHA_BIND_ADDR=0.0.0.0:8080
ENV VARAKSHA_TIER=cloud
ENV VARAKSHA_AUDIT_LOG_PATH=/app/logs/security_audit.jsonl
ENV ORT_DYLIB_PATH=/usr/local/lib/libonnxruntime.so
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}
# Secrets — MUST be set via Railway env vars in production:
# VARAKSHA_API_KEY, VARAKSHA_UPDATE_SECRET, VARAKSHA_GRAPH_SECRET

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["/app/risk-cache"]
