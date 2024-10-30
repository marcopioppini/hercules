TARGET_SERVER := hercules-server
TARGET_MONITOR := hercules-monitor
TARGET_HCP := hcp

CC := gcc
CFLAGS = -O3 -g3 -std=gnu11 -D_GNU_SOURCE -Itomlc99
# CFLAGS += -DNDEBUG
# CFLAGS += -Wall -Wextra

## Options:
# Print rx/tx session stats
CFLAGS += -DPRINT_STATS
# Enforce checking the source SCION/UDP address/port of received packets
# CFLAGS += -DCHECK_SRC_ADDRESS
# Randomise the UDP underlay port (no restriction on the range of used ports).
# Enabling this currently breaks SCMP packet parsing
# CFLAGS += -DRANDOMIZE_UNDERLAY_SRC
# Ignore SCMP error messages, just keep sending
# CFLAGS += -DIGNORE_SCMP

## for debugging:
# ASAN_FLAG := -fsanitize=address
# CFLAGS += -g3 -DDEBUG $(ASAN_FLAG)
#
# CFLAGS += -DDEBUG_PRINT_PKTS # print received/sent packets (lots of noise!)


LDFLAGS = -g3 -l:libbpf.a -Lbpf/src -Ltomlc99 -lm -lelf -latomic -pthread -lz -ltoml -z noexecstack $(ASAN_FLAG)
DEPFLAGS := -MP -MD

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)
MONITORFILES := $(wildcard monitor/*)
HCPFILES := $(wildcard hcp/*)

VERSION := $(shell (ref=$$(git describe --tags --long --dirty 2>/dev/null) && echo $$(git rev-parse --abbrev-ref HEAD)-$$ref) ||\
					echo $$(git rev-parse --abbrev-ref HEAD)-untagged-$$(git describe --tags --dirty --always))
CFLAGS += -DHERCULES_VERSION="\"$(VERSION)\""

PREFIX ?= /usr/local

.PHONY: all install

all: $(TARGET_MONITOR) $(TARGET_SERVER) $(TARGET_HCP)

install:
	install -d $(DESTDIR)$(PREFIX)/bin/
	install $(TARGET_MONITOR) $(DESTDIR)$(PREFIX)/bin/
	install $(TARGET_SERVER) $(DESTDIR)$(PREFIX)/bin/

	install -d $(DESTDIR)$(PREFIX)/etc/
	install hercules.conf $(DESTDIR)$(PREFIX)/etc/

	install -d $(DESTDIR)$(PREFIX)/share/doc/hercules/
	install hercules.conf.sample $(DESTDIR)$(PREFIX)/share/doc/hercules/

	install -d $(DESTDIR)$(PREFIX)/share/man/man1/
	install doc/hercules-server.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install doc/hercules-monitor.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install hcp/hcp.1 $(DESTDIR)$(PREFIX)/share/man/man1/

# List all headers as dependency because we include a header file via cgo (which in turn may include other headers)
$(TARGET_MONITOR): $(MONITORFILES) $(wildcard *.h) builder
	docker exec -w /`basename $(PWD)`/monitor hercules-builder go build -o "../$@" -ldflags "-X main.startupVersion=${VERSION}"

$(TARGET_SERVER): $(OBJS) bpf_prgm/redirect_userspace.o bpf/src/libbpf.a tomlc99/libtoml.a builder
	@# update modification dates in assembly, so that the new version gets loaded
	@sed -i -e "s/\(load bpf_prgm_redirect_userspace\)\( \)\?\([0-9a-f]\{32\}\)\?/\1 $$(md5sum bpf_prgm/redirect_userspace.c | head -c 32)/g" bpf_prgms.s
	docker exec hercules-builder $(CC) -o $@ $(OBJS) bpf_prgms.s $(LDFLAGS)

$(TARGET_HCP): $(HCPFILES) $(wildcard *.h) builder
	docker exec -w /`basename $(PWD)`/hcp hercules-builder go build -ldflags "-X main.startupVersion=${VERSION}"

%.o: %.c builder
	docker exec hercules-builder $(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

hercules: builder hercules.h hercules.go hercules.c bpf_prgm/redirect_userspace.o bpf/src/libbpf.a
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

tomlc99/libtoml.a: builder
	@if [ ! -d tomlc99 ]; then \
		echo "Error: Need libtoml submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		docker exec -w /`basename $(PWD)`/tomlc99 hercules-builder $(MAKE) all; \
	fi


.PHONY: builder builder_image clean

# mockules: builder mockules/main.go mockules/network.go
# 	docker exec -w /`basename $(PWD)`/mockules hercules-builder go build

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

MANFILES := $(wildcard doc/*.[157]) hcp/hcp.1
MDFILES := $(addsuffix .md,$(MANFILES))

%.md: $(basename %)
# Show linter output for all warning levels, but continue if it's not severe
	mandoc -T lint -Wall $< || true
	mandoc -T markdown -W warning,stop $< > $@

docs: $(MDFILES)

-include $(DEPS)
