# notnet - Docker test image
FROM debian:bookworm-slim AS builder

# SECURITY FIX (#130): global killswitch domain baked in at build time.
# Override to arm the killswitch, e.g. --build-arg KILLSWITCH_DOMAIN=ks.example
ARG KILLSWITCH_DOMAIN=killswitch.invalid

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc-dev make && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
# Inject the killswitch domain into config.h (sed, no -D quoting layers).
# Default killswitch.invalid is a no-op replacement, so stock builds
# keep the inert RFC 2606 domain.
# The value is validated against the hostname charset first (#244): an
# unescaped build arg containing /, & or \ would corrupt the sed replacement
# and silently arm the killswitch (#130) with the wrong domain. Restricting to
# [A-Za-z0-9.-] makes the sed substitution injection-proof by construction.
RUN echo "${KILLSWITCH_DOMAIN}" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$' \
    || { echo "FATAL: KILLSWITCH_DOMAIN must be a bare hostname ([A-Za-z0-9.-], no / \\ &), got '${KILLSWITCH_DOMAIN}'" >&2; exit 1; } \
 && sed -i "s/killswitch\.invalid/${KILLSWITCH_DOMAIN}/" include/config.h \
 && make clean && make

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends libc6 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/notnet /usr/local/bin/notnet

USER 1000:1000
CMD ["notnet"]
