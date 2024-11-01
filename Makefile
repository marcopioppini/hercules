TARGET_SERVER := hercules-server
TARGET_MONITOR := hercules-monitor
TARGET_HCP := hcp/hcp

CC := clang
CFLAGS = -O3 -g3 -std=gnu11 -D_GNU_SOURCE -Itomlc99
# CFLAGS += -DNDEBUG
CFLAGS += -Wall -Wextra

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
HCPFILES := $(filter-out $(TARGET_HCP),$(wildcard hcp/*))

VERSION := $(shell (ref=$$(git describe --tags --long --dirty 2>/dev/null) && echo $$(git rev-parse --abbrev-ref HEAD)-$$ref) ||\
					echo $$(git rev-parse --abbrev-ref HEAD)-untagged-$$(git describe --tags --dirty --always))
CFLAGS += -DHERCULES_VERSION="\"$(VERSION)\""

PREFIX ?= /usr/local

.PHONY: all install

all: $(TARGET_MONITOR) $(TARGET_SERVER) $(TARGET_HCP)

install: all
	install -d $(DESTDIR)$(PREFIX)/bin/
	install $(TARGET_MONITOR) $(DESTDIR)$(PREFIX)/bin/
	install $(TARGET_SERVER) $(DESTDIR)$(PREFIX)/bin/
	install $(TARGET_HCP) $(DESTDIR)$(PREFIX)/bin/

	install -d $(DESTDIR)$(PREFIX)/etc/
	install hercules.conf $(DESTDIR)$(PREFIX)/etc/

	install -d $(DESTDIR)$(PREFIX)/share/doc/hercules/
	install hercules.conf.sample $(DESTDIR)$(PREFIX)/share/doc/hercules/

	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system/
	install dist/hercules-monitor.service $(DESTDIR)$(PREFIX)/lib/systemd/system/
	install dist/hercules-server.service $(DESTDIR)$(PREFIX)/lib/systemd/system/

	install -d $(DESTDIR)$(PREFIX)/share/man/man1/
	install doc/hercules-server.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install doc/hercules-monitor.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install hcp/hcp.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -d $(DESTDIR)$(PREFIX)/share/man/man5/
	install doc/hercules.conf.5 $(DESTDIR)$(PREFIX)/share/man/man5/
	install -d $(DESTDIR)$(PREFIX)/share/man/man7/
	install doc/hercules.7 $(DESTDIR)$(PREFIX)/share/man/man7/

# Hack to allow building both in docker and natively:
# Prefixing the target with docker_ should use the builder image.
# e.g., make docker_all
docker_%: builder
	docker exec hercules-builder $(MAKE) $*

# List all headers as dependency because we include a header file via cgo (which in turn may include other headers)
$(TARGET_MONITOR): $(MONITORFILES) $(wildcard *.h)
	cd monitor && go build -o "../$@" -ldflags "-X main.startupVersion=${VERSION}"

$(TARGET_SERVER): $(OBJS) bpf_prgm/redirect_userspace.o bpf/src/libbpf.a tomlc99/libtoml.a
	@# update modification dates in assembly, so that the new version gets loaded
	@sed -i -e "s/\(load bpf_prgm_redirect_userspace\)\( \)\?\([0-9a-f]\{32\}\)\?/\1 $$(md5sum bpf_prgm/redirect_userspace.c | head -c 32)/g" bpf_prgms.s
	$(CC) -o $@ $(OBJS) bpf_prgms.s $(LDFLAGS)

$(TARGET_HCP): $(HCPFILES) $(wildcard *.h)
	cd hcp && go build -ldflags "-X main.startupVersion=${VERSION}"

hcp: $(TARGET_HCP)

%.o: %.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

bpf_prgm/%.ll: bpf_prgm/%.c
	clang -S -target bpf -D __BPF_TRACING__ -I. -Wall -O2 -emit-llvm -c -g -o $@ $<

bpf_prgm/%.o: bpf_prgm/%.ll
	llc -march=bpf -filetype=obj -o $@ $<

# explicitly list intermediates for dependency resolution
bpf_prgm/redirect_userspace.ll:

bpf/src/libbpf.a:
	@if [ ! -d bpf/src ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd bpf/src && $(MAKE) all OBJDIR=.; \
		mkdir -p build; \
		cd bpf/src && $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

tomlc99/libtoml.a:
	@if [ ! -d tomlc99 ]; then \
		echo "Error: Need libtoml submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd tomlc99 && $(MAKE) all; \
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


MANFILES := $(wildcard doc/*.[157]) hcp/hcp.1
MDFILES := $(addsuffix .md,$(MANFILES))

%.md: $(basename %)
# Show linter output for all warning levels, but continue if it's not severe
	mandoc -T lint -Wall $< || true
	mandoc -T markdown -W warning,stop $< > $@

docs: $(MDFILES)

# Packages
# Relies on the fpm tool to build packages.
# More arguments to fpm are specified in the file .fpm
# The package is called hercules-server, because there is already
# one named hercules in Ubuntu's default repos.
PKG_VERSION ?= $(shell git describe --tags 2>/dev/null)

.PHONY: packages pkg_deb pkg_rpm pkg_tar
packages: pkg_deb pkg_rpm pkg_tar
pkg_deb:
	@$(if $(PKG_VERSION),,$(error PKG_VERSION not set and no git tag!))
	@echo Packaging version $(PKG_VERSION)
	mkdir pkgroot
	DESTDIR=pkgroot $(MAKE) install
	fpm -t deb --version $(PKG_VERSION)
	rm -rf pkgroot
pkg_rpm:
	@$(if $(PKG_VERSION),,$(error PKG_VERSION not set and no git tag!))
	@echo Packaging version $(PKG_VERSION)
	mkdir pkgroot
	DESTDIR=pkgroot $(MAKE) install
	fpm -t rpm --version $(PKG_VERSION)
	rm -rf pkgroot
pkg_tar:
	@$(if $(PKG_VERSION),,$(error PKG_VERSION not set and no git tag!))
	@echo Packaging version $(PKG_VERSION)
	mkdir pkgroot
	DESTDIR=pkgroot $(MAKE) install
	fpm -t tar --version $(PKG_VERSION)
	rm -rf pkgroot

clean:
	rm -rf $(TARGET_MONITOR) $(TARGET_SERVER) $(TARGET_HCP) $(OBJS) $(DEPS)
	rm -rf pkgroot *.deb *.rpm *.tar
	rm -f hercules mockules/mockules
	docker container rm -f hercules-builder || true
	docker rmi hercules-builder || true

-include $(DEPS)
