FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    dpdk-dev \
    libnuma-dev \
    python3 \
    curl \
    git \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Bazelisk as "bazel" (arch-aware for ARM Macs)
ARG TARGETARCH
RUN curl -fSL https://github.com/bazelbuild/bazelisk/releases/download/v1.25.0/bazelisk-linux-${TARGETARCH} \
    -o /usr/local/bin/bazel && chmod +x /usr/local/bin/bazel

# Use system JDK instead of Bazel's bundled one (fixes ARM64 JVM crash)
RUN echo "startup --server_javabase=$(dirname $(dirname $(readlink -f $(which java))))" > /etc/bazel.bazelrc
