# syntax=docker/dockerfile:1.25
FROM registry.access.redhat.com/ubi9/python-311:9.8-1779945715

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
COPY scripts/container-download-verified.sh /usr/local/lib/container-download-verified.sh
COPY scripts/install-galaxy-content.sh /usr/local/bin/install-galaxy-content
COPY scripts/ee-entrypoint.sh /usr/local/bin/ee-entrypoint

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
# Python deps via requirements.txt
################################################################################
ARG PIP_TIMEOUT=120
ARG PIP_RETRIES=5
ARG PIP_VERSION=26.1.2

COPY requirements.txt /build/requirements.txt

RUN python -m pip install --no-cache-dir --upgrade "pip==${PIP_VERSION}" && \
    python -m pip install --no-cache-dir \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" \
      -r /build/requirements.txt && \
    rm -f /build/requirements.txt && \
    ansible --version && ansible-galaxy --version && ansible-runner --version

################################################################################
# Terraform
################################################################################
ARG TERRAFORM_VERSION=1.15.7
RUN set -euo pipefail; \
    source /usr/local/lib/container-download-verified.sh; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) tf_arch="amd64" ;; \
      aarch64|arm64) tf_arch="arm64" ;; \
      *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    tf_url="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${tf_arch}.zip"; \
    download_verified \
      "${tf_url}" \
      /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS" \
      "terraform_${TERRAFORM_VERSION}_linux_${tf_arch}.zip"; \
    unzip -q /tmp/terraform.zip -d /usr/local/bin && \
    rm -f /tmp/terraform.zip && \
    /usr/local/bin/terraform -version

################################################################################
# Terragrunt
################################################################################
ARG TERRAGRUNT_VERSION=1.1.0
RUN set -euo pipefail; \
    source /usr/local/lib/container-download-verified.sh; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) tg_arch="amd64" ;; \
      aarch64|arm64) tg_arch="arm64" ;; \
      *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    tg_url="https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/terragrunt_linux_${tg_arch}"; \
    download_verified \
      "${tg_url}" \
      /usr/local/bin/terragrunt \
      "https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/SHA256SUMS" \
      "terragrunt_linux_${tg_arch}"; \
    chmod 0755 /usr/local/bin/terragrunt && \
    /usr/local/bin/terragrunt --version

################################################################################
# Helm
################################################################################
ARG HELM_VERSION=3.21.2
RUN set -euo pipefail; \
    source /usr/local/lib/container-download-verified.sh; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) helm_arch="amd64" ;; \
      aarch64|arm64) helm_arch="arm64" ;; \
      *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    helm_url="https://get.helm.sh/helm-v${HELM_VERSION}-linux-${helm_arch}.tar.gz"; \
    download_verified \
      "${helm_url}" \
      /tmp/helm.tar.gz \
      "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${helm_arch}.tar.gz.sha256sum" \
      "helm-v${HELM_VERSION}-linux-${helm_arch}.tar.gz"; \
    tar -xzf /tmp/helm.tar.gz -C /tmp && \
    install -m 0755 "/tmp/linux-${helm_arch}/helm" /usr/local/bin/helm && \
    rm -rf /tmp/helm.tar.gz "/tmp/linux-${helm_arch}" && \
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
