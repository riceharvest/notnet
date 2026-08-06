# notnet - Build system
# Pure C, cross-platform, multi-architecture

CC ?= gcc
CFLAGS := -Wall -Wextra -O2 -static
LDFLAGS :=

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
        src/util.c

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

# ── Help ─────────────────────────────────────────────────
help:
	@echo "notnet build system"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build for current architecture"
	@echo "  clean        Remove build artifacts"
	@echo "  dist         Create distribution archive"
	@echo "  help         Show this help"
	@echo ""
	@echo "Architecture-specific targets:"
	@echo "  build-x86_64    Build for x86_64"
	@echo "  build-armv7l    Build for ARMv7"
	@echo "  build-aarch64   Build for ARM64"
	@echo "  build-riscv64   Build for RISC-V"
	@echo ""
	@echo "Cross-compilation requires target toolchains"
	@echo "Example: make build-x86_64"

.PHONY: all clean dist help
