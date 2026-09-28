FROM rust:1-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
RUN mkdir src src/bin && echo 'fn main(){}' > src/main.rs && echo 'fn main(){}' > src/bin/mirror.rs && echo 'fn main(){}' > src/bin/compare.rs && cargo build --release && rm -rf src
COPY src ./src
RUN touch src/main.rs src/bin/mirror.rs src/bin/compare.rs && cargo build --release

# io_uring needs a real (glibc) libc at syscall setup time on some kernels; keep a small glibc base.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/syslog-receiver-rs /usr/local/bin/
COPY --from=builder /app/target/release/mirror /usr/local/bin/
COPY --from=builder /app/target/release/compare /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/syslog-receiver-rs"]
