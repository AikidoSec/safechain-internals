FROM quay.io/centos/centos:stream10

RUN dnf install -y \
    rpm-build \
    rpmdevtools \
    make \
    git \
    curl \
    gcc \
    gcc-c++ \
    openssl-devel \
    perl \
    sudo \
    && dnf clean all

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
WORKDIR /workspaces
