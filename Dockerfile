# syntax=docker/dockerfile:1

FROM ubuntu:24.04

# Install core packaging tools
RUN apt update && apt install -y \
    rpm \
    build-essential \
    reprepro \
    dpkg-dev debhelper fakeroot \
    python3 python3-pip \
    gnupg \
    zip unzip \
    curl wget git \
    mono-complete \
    && rm -rf /var/lib/apt/lists/* && \
    wget https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -O /usr/local/bin/nuget && \
    chmod +x /usr/local/bin/nuget

# # Install Chocolatey CLI for Windows packaging
RUN mkdir -p /opt/choco && \
    curl -L https://community.chocolatey.org/install.ps1 -o /opt/choco/install.ps1 && \
    pwsh -NoProfile -ExecutionPolicy Bypass -File /opt/choco/install.ps1 || true

# # Add helper user
# # RUN useradd -ms /bin/bash builder
# # USER builder
# # WORKDIR /home/builder

# # Pre-create directories
# RUN mkdir -p /app/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
# RUN mkdir -p /home/builder/work/dist

# COPY build/makefile /app/makefile

# # Default working directory for mounting
WORKDIR /app
ENV GNUPGHOME=/root/.gnupg
