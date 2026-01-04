FROM registry.access.redhat.com/ubi9/python-311:9.7-1766406230

LABEL maintainer="Lightning IT"
LABEL org.opencontainers.image.title="ee-wunder-ansible-ubi9"
LABEL org.opencontainers.image.description="Ansible Execution Environment (UBI 9) for Wunder automation (AAP + ansible-navigator)."
LABEL org.opencontainers.image.source="https://github.com/lightning-it/container-ee-wunder-ansible-ubi9"

ARG ANSIBLE_GALAXY_CLI_COLLECTION_OPTS=
ARG PKGMGR_OPTS="--nodocs --setopt=install_weak_deps=0 --setopt=*.module_hotfixes=1"

USER 0
# DL4006: ensure pipefail is enabled before any RUN that uses pipes
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

########################
# RPMs via bindep
########################
COPY bindep.txt /build/bindep.txt

# hadolint ignore=SC2086
RUN set -euo pipefail; \
    mapfile -t pkgs < <(grep -Ev '^\s*#|^\s*$' /build/bindep.txt | awk '{print $1}'); \
    dnf -y update; \
    if (( ${#pkgs[@]} )); then \
      echo "Installing bindep RPMs: ${pkgs[*]}"; \
      dnf -y install ${PKGMGR_OPTS} "${pkgs[@]}"; \
    else \
      echo "No bindep RPMs to install."; \
    fi; \
    dnf -y clean all; \
    rm -rf /var/cache/dnf /var/cache/yum; \
    rm -f /build/bindep.txt

########################
# Python deps via requirements.txt
########################
ARG PIP_TIMEOUT=120
ARG PIP_RETRIES=5

COPY requirements.txt /build/requirements.txt

RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" \
      -r /build/requirements.txt && \
    rm -f /build/requirements.txt && \
    ansible --version && ansible-galaxy --version && ansible-runner --version

########################
# EE layout (AAP/Controller uses /runner)
########################
RUN mkdir -p \
      /runner \
      /runner/project \
      /runner/project/roles \
      /runner/roles \
      /runner/inventory \
      /runner/env \
      /runner/.ansible/tmp \
      /tmp/ansible/tmp \
      /usr/share/ansible/collections \
      /usr/share/ansible/roles \
      /usr/share/automation-controller/collections && \
    chmod 0775 /runner /runner/project /runner/project/roles /runner/roles /runner/inventory /runner/env && \
    chmod 1777 /tmp/ansible /tmp/ansible/tmp

ENV HOME=/runner \
    ANSIBLE_LOCAL_TEMP=/tmp/ansible/tmp \
    ANSIBLE_REMOTE_TEMP=/tmp/ansible/tmp \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections:/usr/share/automation-controller/collections:/runner/project/collections:/runner/collections \
    ANSIBLE_ROLES_PATH=/usr/share/ansible/roles:/runner/project/roles:/runner/roles

########################
# Install collections/roles from repo requirements
########################
WORKDIR /build

# --- Collections (standard) ---
COPY collections/requirements.yml /build/collections-requirements.yml
RUN ansible-galaxy collection install ${ANSIBLE_GALAXY_CLI_COLLECTION_OPTS} \
      -r /build/collections-requirements.yml \
      --collections-path /usr/share/ansible/collections && \
    ansible-galaxy collection list -p /usr/share/ansible/collections

# --- Roles (guarded) ---
COPY roles/requirements.yml /build/roles-requirements.yml
RUN set -euo pipefail; \
    if grep -Eq '^[[:space:]]*-[[:space:]]*(src|name):' /build/roles-requirements.yml; then \
      ansible-galaxy role install \
        -r /build/roles-requirements.yml \
        -p /usr/share/ansible/roles && \
      ansible-galaxy role list -p /usr/share/ansible/roles; \
    else \
      echo "No roles to install (roles/requirements.yml empty or no valid entries). Skipping."; \
    fi

# --- Controller Collections (guarded) ---
COPY collections/controller-requirements.yml /build/controller-requirements.yml
RUN set -euo pipefail; \
    if grep -Eq '^[[:space:]]*collections:[[:space:]]*$|^[[:space:]]*-[[:space:]]*name:' /build/controller-requirements.yml; then \
      ansible-galaxy collection install ${ANSIBLE_GALAXY_CLI_COLLECTION_OPTS} \
        -r /build/controller-requirements.yml \
        --collections-path /usr/share/automation-controller/collections && \
      ansible-galaxy collection list -p /usr/share/automation-controller/collections; \
    else \
      echo "No controller collections to install (collections/controller-requirements.yml empty or no valid entries). Skipping."; \
    fi

########################
# Runtime user
########################
RUN useradd -u 1000 -m -d /runner runner && \
    chown -R runner:runner /runner /tmp/ansible /usr/share/ansible /usr/share/automation-controller

USER runner
WORKDIR /runner

CMD ["/bin/bash"]
