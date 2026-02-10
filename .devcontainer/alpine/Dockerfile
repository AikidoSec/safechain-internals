FROM golang:1.25-alpine AS go-builder

FROM alpine:3.21

COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:${PATH}"
ENV GOPATH="/root/go"

RUN apk add --no-cache \
    build-base git make curl sudo pkgconf \
    rpm \
    ruby ruby-dev \
    nodejs npm py3-pip \
    wayland-dev libx11-dev libxkbcommon-dev mesa-dev libxcursor-dev vulkan-loader-dev libffi-dev \
    perl dpkg dpkg-dev xz wget

RUN gem install fpm --no-document

RUN cd /tmp && \
    wget -q "https://deb.debian.org/debian/pool/main/a/alien/alien_8.95.8.tar.xz" && \
    tar xf alien_8.95.8.tar.xz && \
    cd alien && perl Makefile.PL && make && make install && \
    cd / && rm -rf /tmp/alien*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

WORKDIR /workspace
