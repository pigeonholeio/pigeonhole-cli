FROM rockylinux:9

RUN dnf update -y && dnf install -y \
    rpm-build squashfs-tools rpm-sign rpmdevtools make git gcc tar gzip gnupg rubygems \
    createrepo \
    && \
    dnf clean all && \
    gem install fpm && \
    rm -rf /root/.gnupg/*



WORKDIR /app

ENV GNUPGHOME=/root/.gnupg
