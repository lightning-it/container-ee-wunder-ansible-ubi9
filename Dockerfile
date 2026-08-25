# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS patched-tools

ARG TERRAFORM_VERSION=1.15.9
ARG TERRAFORM_COMMIT=87488977e32a400445e0c0b4d95c0713a5eee941
ARG TERRAGRUNT_VERSION=1.1.3
ARG TERRAGRUNT_COMMIT=54c43a44c62c3171c0279951cf44877af1a2ecb3
ARG HELM_VERSION=3.21.4
ARG HELM_COMMIT=813176c51bb5c181dbbd7901298ddcc104cd3417
ARG HELM_ORAS_VERSION=2.6.2
ARG TERRAGRUNT_X_MOD_VERSION=0.40.0

COPY scripts/build-patched-go-tools.sh /usr/local/bin/build-patched-go-tools
RUN chmod 0755 /usr/local/bin/build-patched-go-tools && \
    /usr/local/bin/build-patched-go-tools

FROM registry.access.redhat.com/ubi9/python-311:9.8-1779945715@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c

LABEL maintainer="Lightning IT"
LABEL org.opencontainers.image.title="ee-wunder-ansible-ubi9"
LABEL org.opencontainers.image.description="Ansible Execution Environment (UBI 9) for Wunder automation (AAP + ansible-navigator)."
LABEL org.opencontainers.image.source="https://github.com/lightning-it/container-ee-wunder-ansible-ubi9"

ARG ANSIBLE_GALAXY_CLI_COLLECTION_OPTS=
ARG PKGMGR_OPTS="--nodocs --setopt=install_weak_deps=0 --setopt=*.module_hotfixes=1"
ARG COLLECTION_PROFILE=public
ARG AUTOMATION_HUB_URL="https://console.redhat.com/api/automation-hub/content/published/"
ARG AUTOMATION_HUB_SSO_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
ARG ANSIBLE_GALAXY_INSTALL_RETRIES=5
ARG ANSIBLE_GALAXY_RETRY_DELAY_SECONDS=10

USER 0
# DL4006: ensure pipefail is enabled before any RUN that uses pipes
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

################################################################################
# RPMs via bindep
################################################################################
COPY bindep.txt /build/bindep.txt
COPY scripts/install-galaxy-content.sh /usr/local/bin/install-galaxy-content
COPY scripts/ee-entrypoint.sh /usr/local/bin/ee-entrypoint
COPY --from=patched-tools /out/terraform /usr/local/bin/terraform
COPY --from=patched-tools /out/terragrunt /usr/local/bin/terragrunt
COPY --from=patched-tools /out/helm /usr/local/bin/helm

# hadolint ignore=SC2086
RUN set -euo pipefail; \
    mapfile -t pkgs < <(grep -Ev '^\s*#|^\s*$' /build/bindep.txt | awk '{print $1}'); \
    pkgs+=(ca-certificates nss_wrapper); \
    dnf -y update; \
    if (( ${#pkgs[@]} )); then \
      echo "Installing bindep RPMs: ${pkgs[*]}"; \
      dnf -y install ${PKGMGR_OPTS} "${pkgs[@]}"; \
    else \
      echo "No bindep RPMs to install."; \
    fi; \
    dnf -y clean all; \
    rm -rf /var/cache/dnf /var/cache/yum; \
    rm -f /build/bindep.txt; \
    chmod 0755 /usr/local/bin/install-galaxy-content /usr/local/bin/ee-entrypoint

################################################################################
# Python deps via hash-pinned requirements.lock
################################################################################
ARG PIP_TIMEOUT=120
ARG PIP_RETRIES=5
ARG PIP_VERSION=26.2.1

COPY requirements.txt /build/requirements.txt
COPY requirements.lock /build/requirements.lock
COPY pip.lock /build/pip.lock
COPY scripts/ansible-galaxy.py /build/ansible-galaxy.py

RUN python -m pip install --no-cache-dir --upgrade \
      --require-hashes -r /build/pip.lock && \
    python -m pip install --no-cache-dir \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" \
      --require-hashes -r /build/requirements.lock && \
    galaxy_bin="$(command -v ansible-galaxy)" && \
    install -m 0755 /build/ansible-galaxy.py "${galaxy_bin}" && \
    rm -f /build/ansible-galaxy.py /build/pip.lock /build/requirements.txt /build/requirements.lock && \
    ansible --version && ansible-galaxy --version && ansible-runner --version

RUN set -euo pipefail; \
    chmod 0755 /usr/local/bin/terraform /usr/local/bin/terragrunt /usr/local/bin/helm; \
    /usr/local/bin/terraform -version; \
    /usr/local/bin/terragrunt --version; \
    /usr/local/bin/helm version --short

################################################################################
# EE layout (AAP/Controller uses /runner)
################################################################################
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

################################################################################
# Install collections/roles from repo requirements
################################################################################
WORKDIR /build

# --- Collections (public/certified/none) ---
COPY collections/requirements-base.yml /build/collections-requirements-base.yml
COPY collections/requirements-certified-extra.yml /build/collections-requirements-certified-extra.yml
RUN --mount=type=secret,id=rh_automation_hub_token,required=false \
    install-galaxy-content collections

# --- Roles (guarded) ---
COPY roles/requirements.yml /build/roles-requirements.yml
RUN install-galaxy-content roles

# --- Controller Collections (guarded) ---
COPY collections/controller-requirements.yml /build/controller-requirements.yml
RUN --mount=type=secret,id=rh_automation_hub_token,required=false \
    install-galaxy-content controller

################################################################################
# Runtime user
################################################################################
RUN useradd -u 1000 -m -d /runner runner && \
    chown -R runner:runner /runner /tmp/ansible /usr/share/ansible /usr/share/automation-controller

USER runner
WORKDIR /runner

ENTRYPOINT ["/usr/local/bin/ee-entrypoint"]
CMD ["/bin/bash"]
