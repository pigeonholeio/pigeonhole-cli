# FROM rockylinux:9
# COPY pigeonhole-cli/0.4.19/linux/amd64/pigeonhole /usr/bin
# WORKDIR
# ENTRYPOINT ["/pigeonhole"]

# Use Rocky Linux 9 as the base image
FROM rockylinux:9
ARG VERSION
ARG OS
ARG ARCH
# Set up environment variables
ENV HOME=/home/pigeonhole
ENV USER=pigeonhole
# Add a non-root user called pigeonhole with a home directory
RUN useradd -m -s /bin/bash pigeonhole
# Install bash-completion
RUN yum update -y && \
    yum install -y bash-completion && \
    yum clean all

COPY pigeonhole-cli/$VERSION/$OS/$ARCH/pigeonhole /usr/bin/pigeonhole
# Create a bash completion script for pigeonhole-cli
RUN chmod +x /usr/bin/pigeonhole && pigeonhole completion bash >> /home/pigeonhole/.bash_profile

# Change ownership of the home directory to the new user
RUN chown -R pigeonhole:pigeonhole /home/pigeonhole

# Switch to the non-root user
USER pigeonhole

# Set the working directory
WORKDIR /home/pigeonhole

# Entry point (bash shell by default)
CMD ["/bin/bash"]
