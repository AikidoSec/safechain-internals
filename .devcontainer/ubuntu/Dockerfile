FROM golang:1.25 AS go-builder

FROM ubuntu:24.04

COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:${PATH}"
ENV GOPATH="/root/go"

RUN apt-get update && apt-get install -y \
    build-essential git make curl sudo pkg-config \
    rpm alien \
    ruby ruby-dev \
    nodejs npm python3-pip \
    libwayland-dev libx11-dev libx11-xcb-dev libxkbcommon-x11-dev \
    libgles2-mesa-dev libegl1-mesa-dev libffi-dev libxcursor-dev libvulkan-dev \
    && gem install fpm --no-document \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

WORKDIR /workspace
