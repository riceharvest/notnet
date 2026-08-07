# notnet - Docker test image
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc-dev make && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN make clean && make

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends libc6 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/notnet /usr/local/bin/notnet

USER 1000:1000
CMD ["notnet"]
