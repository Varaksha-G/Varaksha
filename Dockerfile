# -- Stage 1: Rust build -------------------------------------------------------
FROM rust:1.75-slim as rust-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY gateway/ ./gateway/
COPY risk-cache/ ./risk-cache/
RUN cargo build --release --manifest-path gateway/Cargo.toml

# -- Stage 2: Final runtime image ---------------------------------------------
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=rust-builder /app/target/release/varaksha-gateway ./varaksha-gateway
COPY services/local_engine/ ./services/local_engine/
COPY services/api/ ./services/api/
COPY data/models/ ./data/models/
COPY start.sh .

RUN chmod +x start.sh varaksha-gateway

EXPOSE 7860
CMD ["./start.sh"]
