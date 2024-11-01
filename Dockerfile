# ubuntu/focal with go-1.22.8
# copy pasted from
# https://github.com/docker-library/golang/blob/master/1.21/bullseye/Dockerfile
# but with a different base image (ubuntu:focal instead of debian:bullseye)

FROM ubuntu:focal
ARG UID=1001
ARG GID=1001

# to avoid interactive timezone query
ENV TZ Europe/Zürich
ENV DEBIAN_FRONTEND noninteractive

# install cgo-related dependencies
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		g++ \
		gcc \
		libc6-dev \
		make \
		pkg-config \
		wget \
		git \
		apt-transport-https \
		ca-certificates \
		libelf-dev \
		vim less \
		gpg \
		gpg-agent \
		dirmngr \
		clang \
		llvm \
		libelf-dev \
		libpcap-dev \
		gcc-multilib \
		build-essential \
        ruby \
        rpm \
	; \
	rm -rf /var/lib/apt/lists/*

ENV PATH /usr/local/go/bin:$PATH

RUN gem install dotenv -v 2.8.1
RUN gem install fpm

ENV GOLANG_VERSION 1.22.8

RUN set -eux; \
	arch="$(dpkg --print-architecture)"; arch="${arch##*-}"; \
	url=; \
	case "$arch" in \
		'amd64') \
			url='https://go.dev/dl/go1.22.8.linux-amd64.tar.gz'; \
			sha256='5f467d29fc67c7ae6468cb6ad5b047a274bae8180cac5e0b7ddbfeba3e47e18f'; \
			;; \
		*) echo >&2 "error: unsupported architecture '$arch' (likely packaging update needed)"; exit 1 ;; \
	esac; \
	\
	wget -O go.tgz.asc "$url.asc"; \
	wget -O go.tgz "$url" --progress=dot:giga; \
	echo "$sha256 *go.tgz" | sha256sum -c -; \
	\
# https://github.com/golang/go/issues/14739#issuecomment-324767697
	GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
# https://www.google.com/linuxrepositories/
	gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 'EB4C 1BFD 4F04 2F6D DDCC  EC91 7721 F63B D38B 4796'; \
# let's also fetch the specific subkey of that key explicitly that we expect "go.tgz.asc" to be signed by, just to make sure we definitely have it
	gpg --batch --keyserver keyserver.ubuntu.com --recv-keys '2F52 8D36 D67B 69ED F998  D857 78BD 6547 3CB3 BD13'; \
	gpg --batch --verify go.tgz.asc go.tgz; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" go.tgz.asc; \
	\
	tar -C /usr/local -xzf go.tgz; \
	rm go.tgz; \
	\
	go version

# don't auto-upgrade the gotoolchain
# https://github.com/docker-library/golang/issues/472
ENV GOTOOLCHAIN=local

RUN groupadd --gid $GID --non-unique buildboy
RUN useradd buildboy --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID
USER buildboy
WORKDIR /home/buildboy
RUN mkdir go
ENV GOPATH /home/buildboy/go
ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH
