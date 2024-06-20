# TODO change binary names
TARGET_SERVER := runHercules
TARGET_MONITOR := runMonitor

CC := gcc
CFLAGS = -O0 -std=gnu11 -D_GNU_SOURCE
# CFLAGS += -Wall -Wextra
# for debugging:
# ASAN_FLAG := -fsanitize=address,leak,undefined,pointer-compare,pointer-subtract
ASAN_FLAG := -fsanitize=address
CFLAGS += -g3 -DDEBUG $(ASAN_FLAG)
# CFLAGS += -DDEBUG_PRINT_PKTS # print received/sent packets
# CFLAGS += -DPRINT_STATS
# CFLAGS += -DRANDOMIZE_UNDERLAY_SRC # Enabling this breaks SCMP packet parsing
LDFLAGS = -lbpf -Lbpf/src -lm -lelf -pthread -lz -z noexecstack $(ASAN_FLAG)
DEPFLAGS:=-MP -MD

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)
MONITORFILES := $(wildcard monitor/*)

VERSION := $(shell (ref=$$(git describe --tags --long --dirty 2>/dev/null) && echo $$(git rev-parse --abbrev-ref HEAD)-$$ref) ||\
					echo $$(git rev-parse --abbrev-ref HEAD)-untagged-$$(git describe --tags --dirty --always))

# TODO: Install target
# TODO: Native vs docker builds
all: $(TARGET_MONITOR) $(TARGET_SERVER)

# List all headers as dependency because we include a header file via cgo (which in turn may include other headers)
$(TARGET_MONITOR): $(MONITORFILES) $(wildcard *.h)
	cd monitor && go build -o "../$@" -ldflags "-X main.startupVersion=${VERSION}"

$(TARGET_SERVER): $(OBJS) bpf_prgm/redirect_userspace.o bpf/src/libbpf.a builder
	@# update modification dates in assembly, so that the new version gets loaded
	@sed -i -e "s/\(load bpf_prgm_pass\)\( \)\?\([0-9a-f]\{32\}\)\?/\1 $$(md5sum bpf_prgm/pass.c | head -c 32)/g" bpf_prgms.s
	@sed -i -e "s/\(load bpf_prgm_redirect_userspace\)\( \)\?\([0-9a-f]\{32\}\)\?/\1 $$(md5sum bpf_prgm/redirect_userspace.c | head -c 32)/g" bpf_prgms.s
	docker exec hercules-builder $(CC) -o $@ $(OBJS) bpf_prgms.s $(LDFLAGS)

%.o: %.c builder
	docker exec hercules-builder $(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

hercules: builder hercules.h hercules.go hercules.c bpf_prgm/redirect_userspace.o bpf_prgm/pass.o bpf/src/libbpf.a
	docker exec hercules-builder go build -ldflags "-X main.startupVersion=$${startupVersion}"

bpf_prgm/%.ll: bpf_prgm/%.c
	docker exec hercules-builder clang -S -target bpf -D __BPF_TRACING__ -I. -Wall -O2 -emit-llvm -c -g -o $@ $<

bpf_prgm/%.o: bpf_prgm/%.ll
	docker exec hercules-builder llc -march=bpf -filetype=obj -o $@ $<

# explicitly list intermediates for dependency resolution
bpf_prgm/redirect_userspace.ll:

bpf/src/libbpf.a: builder
	@if [ ! -d bpf/src ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		docker exec -w /`basename $(PWD)`/bpf/src hercules-builder $(MAKE) all OBJDIR=.; \
		mkdir -p build; \
		docker exec -w /`basename $(PWD)`/bpf/src hercules-builder $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi


.PHONY: builder builder_image install clean all

# what to do with this??
mockules: builder mockules/main.go mockules/network.go
	docker exec -w /`basename $(PWD)`/mockules hercules-builder go build

# docker stuff
builder: builder_image
	@docker container ls -a --format={{.Names}} | grep hercules-builder -q || \
		docker run -t --entrypoint cat --name hercules-builder -v $(PWD):/`basename $(PWD)` -w /`basename $(PWD)` -d hercules-builder
	@docker container ls --format={{.Names}} | grep hercules-builder -q || \
		docker start hercules-builder

builder_image:
	@docker images | grep hercules-builder -q || \
		docker build -t hercules-builder --build-arg UID=$(shell id -u) --build-arg GID=$(shell id -g) .

clean:
	rm -rf $(TARGET_MONITOR) $(TARGET_SERVER) $(OBJS) $(DEPS)
	rm -f hercules mockules/mockules
	docker container rm -f hercules-builder || true
	docker rmi hercules-builder || true

-include $(DEPS)
