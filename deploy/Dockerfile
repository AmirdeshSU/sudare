# Build from the repo root:  docker build -f deploy/Dockerfile -t sudare .
FROM rust:1.99.1-slim-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sudare-cli \
 && mkdir -p /out/data && cp target/release/sudare /out/sudare

# distroless/cc: glibc, CA certificates (for rustls' OS trust store), no shell.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /out/sudare /sudare
# The volume mounted here inherits this ownership on first use.
COPY --from=build --chown=65532:65532 /out/data /data
ENV SUDARE_BIND=0.0.0.0:8080 \
    SUDARE_DATA_DIR=/data \
    SUDARE_ALLOWED_HOSTS=localhost:8080,127.0.0.1:8080
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/sudare"]
CMD ["serve"]
