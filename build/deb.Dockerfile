FROM ubuntu:24.04

# Install core packaging tools
RUN apt update && apt install -y \
    rpm \
    golang \
    build-essential \
    sudo \
    curl \
    ruby-rubygems \
    reprepro \
    squashfs-tools \
    dpkg-dev debhelper fakeroot \
    python3 python3-pip \
    gnupg \
    zip unzip \
    curl wget git \
    mono-complete \
    && rm -rf /var/lib/apt/lists/* && \
    wget https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -O /usr/local/bin/nuget && \
    chmod +x /usr/local/bin/nuget && \
    gem install fpm


RUN curl -L https://raw.githubusercontent.com/mh-cbon/latest/master/install.sh | GH=mh-cbon/go-msi sh -xe



    # wget -O /tmp/go-msi.tar.gz https://github.com/mh-cbon/go-msi/releases/download/1.0.3/go-msi-amd64.tar.gz && \
    # tar -xzf /tmp/go-msi.tar.gz -C /usr/local/bin/ && \
    # chmod +x /usr/local/bin/go-msi && \
    # rm /tmp/go-msi.tar.gz

# # Install Chocolatey CLI for Windows packaging
RUN mkdir -p /opt/choco && \
    curl -L https://community.chocolatey.org/install.ps1 -o /opt/choco/install.ps1 && \
    pwsh -NoProfile -ExecutionPolicy Bypass -File /opt/choco/install.ps1 || true
RUN rm -rf /root/.gnupg/*
WORKDIR /app
ENV GNUPGHOME=/root/.gnupg
