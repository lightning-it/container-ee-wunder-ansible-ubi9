FROM registry.access.redhat.com/ubi9/python-311:latest

LABEL maintainer="Lightning IT"
LABEL org.opencontainers.image.title="ee-wunder-ansible-ubi9"
LABEL org.opencontainers.image.description="Ansible Execution Environment (UBI 9) for Wunder automation."
LABEL org.opencontainers.image.source="https://github.com/lightning-it/container-ee-wunder-ansible-ubi9"

ARG ANSIBLE_CORE_VERSION=2.18.0

USER 0

########################
# Base tools for Ansible
########################
RUN microdnf -y update && \
    microdnf -y install \
      bash \
      ca-certificates \
      openssh-clients \
      git && \
    microdnf clean all && \
    rm -rf /var/cache/yum

########################
# Ansible (core)
########################
RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir "ansible-core==${ANSIBLE_CORE_VERSION}" && \
    ansible --version && ansible-galaxy --version

########################
# User & Workdir
########################
WORKDIR /workspace

# Create user + ensure writable HOME + Ansible temp dirs
RUN useradd -m wunder && \
    mkdir -p /home/wunder/.ansible/tmp /tmp/ansible/tmp && \
    chown -R wunder:wunder /workspace /home/wunder && \
    chmod 1777 /tmp/ansible /tmp/ansible/tmp

# Ensure Ansible uses writable locations
ENV HOME=/home/wunder
ENV ANSIBLE_LOCAL_TEMP=/tmp/ansible/tmp
ENV ANSIBLE_REMOTE_TEMP=/tmp/ansible/tmp

USER wunder

# Default
CMD ["/bin/bash"]
