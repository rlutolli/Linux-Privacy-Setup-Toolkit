# Dockerfile for testing privacy-toolkit.sh
# Test on different Linux distributions

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    sudo \
    systemd \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for testing
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy the script
COPY privacy-toolkit.sh /tmp/privacy-toolkit.sh
RUN chmod +x /tmp/privacy-toolkit.sh

# Set working directory
WORKDIR /tmp

# Switch to test user
USER testuser

# Test script syntax
RUN bash -n privacy-toolkit.sh || exit 1

# Note: Full execution would require more setup (systemd, etc.)
# This Dockerfile is mainly for syntax checking and basic validation

