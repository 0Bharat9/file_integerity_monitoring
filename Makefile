# FIM - File Integrity Monitoring using eBPF
# Makefile

# Compiler settings
CC = gcc
BPF_CC = clang
CFLAGS = -g -O2 -Wall -Wextra -lcrypto -lssl
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86

# Libraries
LIBS = -lbpf -lelf -lz -lcrypto

# Directories
SRC_DIR = src
BPF_DIR = bpf
INCLUDE_DIR = include
BUILD_DIR = build

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
BPF_SOURCE = $(BPF_DIR)/fim.bpf.c
HEADERS = $(wildcard $(INCLUDE_DIR)/*.h)

# Object files
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
BPF_OBJECT = $(BUILD_DIR)/fim.bpf.o
SKELETON = $(BUILD_DIR)/fim.skel.h

# Target executable
TARGET = fim

# Default target
all: setup $(TARGET)

# Create build directory
setup:
	@mkdir -p $(BUILD_DIR)

# Generate vmlinux.h if it doesn't exist
vmlinux:
	@if [ ! -f $(INCLUDE_DIR)/vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(INCLUDE_DIR)/vmlinux.h; \
	fi

# Compile eBPF program (only include eBPF-safe headers)
$(BPF_OBJECT): $(BPF_SOURCE) vmlinux $(INCLUDE_DIR)/bpf_fim.h
	$(BPF_CC) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Generate BPF skeleton
$(SKELETON): $(BPF_OBJECT)
	bpftool gen skeleton $< > $@

# Compile C source files (use userspace headers)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) $(SKELETON)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(BUILD_DIR) -c $< -o $@

# Link final executable
$(TARGET): $(OBJECTS) $(BPF_OBJECT)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LIBS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET)

# Clean everything including generated files
distclean: clean
	rm -f $(INCLUDE_DIR)/vmlinux.h
	rm -f *.skel.h
	rm -f *.bpf.o

# Install target (requires root)
install: $(TARGET)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Installation requires root privileges. Run: sudo make install"; \
		exit 1; \
	fi
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "FIM installed to /usr/local/bin/"

# Uninstall target (requires root)
uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Uninstallation requires root privileges. Run: sudo make uninstall"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/$(TARGET)
	@echo "FIM uninstalled from /usr/local/bin/"

# Development targets
dev-setup:
	@echo "Installing development dependencies..."
	@echo "Make sure you have the following packages installed:"
	@echo "- libbpf-dev"
	@echo "- libelf-dev"
	@echo "- zlib1g-dev"
	@echo "- libssl-dev"
	@echo "- bpftool"
	@echo "- clang"
	@echo "- gcc"

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which clang > /dev/null || (echo "ERROR: clang not found" && exit 1)
	@which gcc > /dev/null || (echo "ERROR: gcc not found" && exit 1)
	@which bpftool > /dev/null || (echo "ERROR: bpftool not found" && exit 1)
	@pkg-config --exists libbpf || (echo "ERROR: libbpf-dev not found" && exit 1)
	@pkg-config --exists libelf || (echo "ERROR: libelf-dev not found" && exit 1)
	@pkg-config --exists zlib || (echo "ERROR: zlib1g-dev not found" && exit 1)
	@pkg-config --exists libcrypto || (echo "ERROR: libssl-dev not found" && exit 1)
	@echo "All dependencies found!"

# Debug build
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

# Help target
help:
	@echo "FIM - File Integrity Monitoring using eBPF"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build the FIM executable (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  distclean   - Remove all generated files"
	@echo "  install     - Install FIM to /usr/local/bin (requires root)"
	@echo "  uninstall   - Remove FIM from /usr/local/bin (requires root)"
	@echo "  vmlinux     - Generate vmlinux.h file"
	@echo "  dev-setup   - Show development setup instructions"
	@echo "  check-deps  - Check for required dependencies"
	@echo "  debug       - Build with debug symbols and DEBUG flag"
	@echo "  release     - Build optimized release version"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build FIM"
	@echo "  sudo make install # Install FIM system-wide"
	@echo "  make clean        # Clean build files"

.PHONY: all setup vmlinux clean distclean install uninstall dev-setup check-deps debug release help

