# syntax=docker/dockerfile:1.21
FROM registry.access.redhat.com/ubi9/python-311:9.7-1771432269

LABEL maintainer="Lightning IT"
LABEL org.opencontainers.image.title="ee-wunder-ansible-ubi9"
LABEL org.opencontainers.image.description="Ansible Execution Environment (UBI 9) for Wunder automation (AAP + ansible-navigator)."
LABEL org.opencontainers.image.source="https://github.com/lightning-it/container-ee-wunder-ansible-ubi9"

ARG ANSIBLE_GALAXY_CLI_COLLECTION_OPTS=
ARG PKGMGR_OPTS="--nodocs --setopt=install_weak_deps=0 --setopt=*.module_hotfixes=1"
ARG COLLECTION_PROFILE=public
ARG AUTOMATION_HUB_URL="https://console.redhat.com/api/automation-hub/content/published/"
ARG AUTOMATION_HUB_AUTH_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
ARG ANSIBLE_GALAXY_INSTALL_RETRIES=5
ARG ANSIBLE_GALAXY_RETRY_DELAY_SECONDS=10

USER 0
# DL4006: ensure pipefail is enabled before any RUN that uses pipes
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

################################################################################
# RPMs via bindep
################################################################################
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

################################################################################
# NSS wrapper (fix host UID != image user, e.g. macOS uid 501)
################################################################################
RUN set -euo pipefail; \
    dnf -y install ${PKGMGR_OPTS} nss_wrapper; \
    dnf -y clean all; \
    rm -rf /var/cache/dnf /var/cache/yum

################################################################################
# Python deps via requirements.txt
################################################################################
ARG PIP_TIMEOUT=120
ARG PIP_RETRIES=5
ARG PIP_VERSION=24.3.1

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
ARG TERRAFORM_VERSION=1.14.3
RUN set -euo pipefail; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) tf_arch="amd64" ;; \
      aarch64|arm64) tf_arch="arm64" ;; \
      *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    tf_url="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${tf_arch}.zip"; \
    TF_URL="${tf_url}" python - <<'PY' && \
    unzip -q /tmp/terraform.zip -d /usr/local/bin && \
    rm -f /tmp/terraform.zip && \
    /usr/local/bin/terraform -version
import os
import urllib.request

url = os.environ["TF_URL"]
out_path = "/tmp/terraform.zip"
with urllib.request.urlopen(url) as resp, open(out_path, "wb") as handle:
    handle.write(resp.read())
PY

################################################################################
# Terragrunt
################################################################################
ARG TERRAGRUNT_VERSION=0.97.2
RUN set -euo pipefail; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) tg_arch="amd64" ;; \
      aarch64|arm64) tg_arch="arm64" ;; \
      *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    tg_url="https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/terragrunt_linux_${tg_arch}"; \
    TG_URL="${tg_url}" python - <<'PY' && \
    chmod 0755 /usr/local/bin/terragrunt && \
    /usr/local/bin/terragrunt --version
import os
import urllib.request

url = os.environ["TG_URL"]
out_path = "/usr/local/bin/terragrunt"
with urllib.request.urlopen(url) as resp, open(out_path, "wb") as handle:
    handle.write(resp.read())
PY

################################################################################
# Helm
################################################################################
ARG HELM_VERSION=3.19.0
RUN set -euo pipefail; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) helm_arch="amd64" ;; \
      aarch64|arm64) helm_arch="arm64" ;; \
      *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    helm_url="https://get.helm.sh/helm-v${HELM_VERSION}-linux-${helm_arch}.tar.gz"; \
    HELM_URL="${helm_url}" python - <<'PY' && \
    tar -xzf /tmp/helm.tar.gz -C /tmp && \
    install -m 0755 "/tmp/linux-${helm_arch}/helm" /usr/local/bin/helm && \
    rm -rf /tmp/helm.tar.gz "/tmp/linux-${helm_arch}" && \
    /usr/local/bin/helm version --short
import os
import urllib.request

url = os.environ["HELM_URL"]
out_path = "/tmp/helm.tar.gz"
with urllib.request.urlopen(url) as resp, open(out_path, "wb") as handle:
    handle.write(resp.read())
PY

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

# --- Collections (base + certified extra) ---
COPY collections/requirements-base.yml /build/collections-requirements-base.yml
COPY collections/requirements-certified-extra.yml /build/collections-requirements-certified-extra.yml
RUN --mount=type=secret,id=rh_automation_hub_token,required=false \
    set -euo pipefail; \
    base_req_file="/build/collections-requirements-base.yml"; \
    certified_extra_req_file="/build/collections-requirements-certified-extra.yml"; \
    if [[ ! -f "${base_req_file}" ]]; then \
      echo "Base collections requirements file not found: ${base_req_file}" >&2; \
      exit 1; \
    fi; \
    install_with_retry() { \
      local attempts="${ANSIBLE_GALAXY_INSTALL_RETRIES}"; \
      local delay="${ANSIBLE_GALAXY_RETRY_DELAY_SECONDS}"; \
      local try=1; \
      until "$@"; do \
        if [[ "${try}" -ge "${attempts}" ]]; then \
          return 1; \
        fi; \
        echo "ansible-galaxy failed (attempt ${try}/${attempts}); retrying in ${delay}s..."; \
        sleep "${delay}"; \
        try=$((try + 1)); \
      done; \
    }; \
    galaxy_cmd() { \
      if [[ -f /tmp/ansible-galaxy.cfg ]]; then \
        ANSIBLE_CONFIG=/tmp/ansible-galaxy.cfg ansible-galaxy "$@"; \
      else \
        ansible-galaxy "$@"; \
      fi; \
    }; \
    configure_automation_hub() { \
      token_file="/run/secrets/rh_automation_hub_token"; \
      if [[ ! -s "${token_file}" ]]; then \
        echo "Missing required build secret for certified profile: rh_automation_hub_token" >&2; \
        exit 1; \
      fi; \
      token="$(tr -d '\r\n' < "${token_file}")"; \
      if [[ -z "${token}" ]]; then \
        echo "Build secret rh_automation_hub_token is empty" >&2; \
        exit 1; \
      fi; \
      { \
        echo "[galaxy]"; \
        echo "server_list = automation_hub,galaxy"; \
        echo; \
        echo "[galaxy_server.automation_hub]"; \
        echo "url=${AUTOMATION_HUB_URL}"; \
        echo "auth_url=${AUTOMATION_HUB_AUTH_URL}"; \
        echo "token=${token}"; \
        echo; \
        echo "[galaxy_server.galaxy]"; \
        echo "url=https://galaxy.ansible.com/"; \
      } > /tmp/ansible-galaxy.cfg; \
    }; \
    case "${COLLECTION_PROFILE}" in \
      public) \
        install_certified_extra=false; \
        ;; \
      certified) \
        install_certified_extra=true; \
        ;; \
      *) \
        echo "Invalid COLLECTION_PROFILE='${COLLECTION_PROFILE}' (use: public|certified)" >&2; \
        exit 1; \
        ;; \
    esac; \
    install_with_retry galaxy_cmd collection install ${ANSIBLE_GALAXY_CLI_COLLECTION_OPTS} \
      -r "${base_req_file}" \
      --collections-path /usr/share/ansible/collections; \
    if [[ "${install_certified_extra}" == "true" ]]; then \
      if [[ ! -f "${certified_extra_req_file}" ]]; then \
        echo "Certified extra requirements file not found: ${certified_extra_req_file}" >&2; \
        exit 1; \
      fi; \
      configure_automation_hub; \
      install_with_retry galaxy_cmd collection install ${ANSIBLE_GALAXY_CLI_COLLECTION_OPTS} \
        -r "${certified_extra_req_file}" \
        --collections-path /usr/share/ansible/collections; \
    fi; \
    galaxy_cmd collection list -p /usr/share/ansible/collections; \
    rm -f /tmp/ansible-galaxy.cfg

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
RUN --mount=type=secret,id=rh_automation_hub_token,required=false \
    set -euo pipefail; \
    if grep -Eq '^[[:space:]]*collections:[[:space:]]*$|^[[:space:]]*-[[:space:]]*name:' /build/controller-requirements.yml; then \
      install_with_retry() { \
        local attempts="${ANSIBLE_GALAXY_INSTALL_RETRIES}"; \
        local delay="${ANSIBLE_GALAXY_RETRY_DELAY_SECONDS}"; \
        local try=1; \
        until "$@"; do \
          if [[ "${try}" -ge "${attempts}" ]]; then \
            return 1; \
          fi; \
          echo "ansible-galaxy failed (attempt ${try}/${attempts}); retrying in ${delay}s..."; \
          sleep "${delay}"; \
          try=$((try + 1)); \
        done; \
      }; \
      galaxy_cmd() { \
        if [[ -f /tmp/ansible-galaxy.cfg ]]; then \
          ANSIBLE_CONFIG=/tmp/ansible-galaxy.cfg ansible-galaxy "$@"; \
        else \
          ansible-galaxy "$@"; \
        fi; \
      }; \
      case "${COLLECTION_PROFILE}" in \
        certified) \
          token_file="/run/secrets/rh_automation_hub_token"; \
          if [[ ! -s "${token_file}" ]]; then \
            echo "Missing required build secret for certified profile: rh_automation_hub_token" >&2; \
            exit 1; \
          fi; \
          token="$(tr -d '\r\n' < "${token_file}")"; \
          if [[ -z "${token}" ]]; then \
            echo "Build secret rh_automation_hub_token is empty" >&2; \
            exit 1; \
          fi; \
          { \
            echo "[galaxy]"; \
            echo "server_list = automation_hub,galaxy"; \
            echo; \
            echo "[galaxy_server.automation_hub]"; \
            echo "url=${AUTOMATION_HUB_URL}"; \
            echo "auth_url=${AUTOMATION_HUB_AUTH_URL}"; \
            echo "token=${token}"; \
            echo; \
            echo "[galaxy_server.galaxy]"; \
            echo "url=https://galaxy.ansible.com/"; \
          } > /tmp/ansible-galaxy.cfg; \
          ;; \
        public) \
          ;; \
        *) \
          echo "Invalid COLLECTION_PROFILE='${COLLECTION_PROFILE}' (use: public|certified)" >&2; \
          exit 1; \
          ;; \
      esac; \
      install_with_retry galaxy_cmd collection install ${ANSIBLE_GALAXY_CLI_COLLECTION_OPTS} \
        -r /build/controller-requirements.yml \
        --collections-path /usr/share/automation-controller/collections; \
      galaxy_cmd collection list -p /usr/share/automation-controller/collections; \
      rm -f /tmp/ansible-galaxy.cfg; \
    else \
      echo "No controller collections to install (collections/controller-requirements.yml empty or no valid entries). Skipping."; \
    fi

################################################################################
# EntryPoint: create passwd/group for arbitrary UID (e.g. 501) via nss_wrapper
################################################################################
RUN cat > /usr/local/bin/ee-entrypoint <<'EOF' && chmod 0755 /usr/local/bin/ee-entrypoint
#!/usr/bin/env bash
set -euo pipefail

# If no command is provided, fall back to bash
if [ "$#" -eq 0 ]; then
  set -- /bin/bash
fi

# If current UID has no passwd entry, ansible/ssh may fail ("No user exists for uid ...").
# Use nss_wrapper to provide a synthetic passwd/group entry in /tmp.
if ! whoami >/dev/null 2>&1; then
  uid="$(id -u)"
  gid="$(id -g)"
  home="${HOME:-/tmp}"

  export NSS_WRAPPER_PASSWD="${TMPDIR:-/tmp}/passwd.nss_wrapper"
  export NSS_WRAPPER_GROUP="${TMPDIR:-/tmp}/group.nss_wrapper"

  # Seed from existing files if readable; then append current uid/gid.
  (cat /etc/passwd 2>/dev/null || true) > "${NSS_WRAPPER_PASSWD}"
  echo "eeuser:x:${uid}:${gid}:EE User:${home}:/bin/bash" >> "${NSS_WRAPPER_PASSWD}"

  (cat /etc/group 2>/dev/null || true) > "${NSS_WRAPPER_GROUP}"
  echo "eegroup:x:${gid}:" >> "${NSS_WRAPPER_GROUP}"

  wrapper="/usr/lib64/libnss_wrapper.so"
  if [ -f "${wrapper}" ]; then
    export LD_PRELOAD="${wrapper}${LD_PRELOAD:+:${LD_PRELOAD}}"
  fi
fi

exec "$@"
EOF

################################################################################
# Runtime user
################################################################################
RUN useradd -u 1000 -m -d /runner runner && \
    chown -R runner:runner /runner /tmp/ansible /usr/share/ansible /usr/share/automation-controller

USER runner
WORKDIR /runner

ENTRYPOINT ["/usr/local/bin/ee-entrypoint"]
CMD ["/bin/bash"]
