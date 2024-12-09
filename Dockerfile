# FROM rockylinux:9
# COPY pigeonhole-cli/0.4.19/linux/amd64/pigeonhole /usr/bin
# WORKDIR
# ENTRYPOINT ["/pigeonhole"]

# Use Rocky Linux 9 as the base image
FROM rockylinux:9

# Set up environment variables
ENV HOME /home/pigeonhole
ENV USER pigeonhole
# Add a non-root user called pigeonhole with a home directory
RUN useradd -m -s /bin/bash $USER
# Install bash-completion
RUN yum update -y && \
    yum install -y bash-completion && \
    yum clean all

COPY pigeonhole-cli/{{ .Version }}/ {{ .Os }}/{{ .Arch }}/pigeonhole /usr/bin/pigeonhole
# Create a bash completion script for pigeonhole-cli
RUN chmod +x /usr/bin/pigeonhole && pigeonhole completion bash >> /home/pigeonhole/.bash_profile

# Change ownership of the home directory to the new user
RUN chown -R $USER:$USER $HOME

# Switch to the non-root user
USER $USER

# Set the working directory
WORKDIR $HOME

# Entry point (bash shell by default)
CMD ["/bin/bash"]
