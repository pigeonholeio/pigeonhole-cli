# FROM rockylinux:9
# COPY pigeonhole-cli/0.4.19/linux/amd64/pigeonhole /usr/bin
# WORKDIR
# ENTRYPOINT ["/pigeonhole"]

# Use Rocky Linux 9 as the base image
FROM rockylinux:9
ARG VERSION="0.4.19"
ARG OS="linux"
ARG ARCH="amd64"
# Add a non-root user called pigeonhole with a home directory
RUN useradd -m -s /bin/bash pigeonhole

# RUN chown -R pigeonhole:pigeonhole /home/pigeonhole
# Install bash-completion
RUN yum update -y && \
    yum install -y bash-completion && \
    yum clean all

COPY dist/pigeonhole-cli/$VERSION/$OS/$ARCH/pigeonhole /usr/bin/
# Create a bash completion script for pigeonhole-cli
SHELL ["/bin/bash","-c"]
# RUN pigeonhole completion bash >> /home/pigeonhole/.bash_profile


# Switch to the non-root user
USER pigeonhole

# Set the working directory
WORKDIR /home/pigeonhole

# Entry point (bash shell by default)
CMD ["/bin/bash"]
