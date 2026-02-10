FROM golang:1.25 AS go-builder

FROM quay.io/centos/centos:stream10

COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:${PATH}"
ENV GOPATH="/root/go"

RUN dnf install -y epel-release && \
    dnf config-manager --set-enabled crb && \
    dnf install -y \
    gcc gcc-c++ git make curl sudo pkgconf \
    rpm-build \
    dpkg \
    ruby ruby-devel \
    perl wget xz \
    wayland-devel libX11-devel libxkbcommon-devel libxkbcommon-x11-devel \
    mesa-libGLES-devel mesa-libEGL-devel libffi-devel libXcursor-devel vulkan-loader-devel \
    && gem install fpm --no-document \
    && dnf clean all

RUN cd /tmp && \
    wget -q "https://deb.debian.org/debian/pool/main/a/alien/alien_8.95.8.tar.xz" && \
    tar xf alien_8.95.8.tar.xz && \
    cd alien && perl Makefile.PL && make && make install && \
    cd / && rm -rf /tmp/alien*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

WORKDIR /workspace
