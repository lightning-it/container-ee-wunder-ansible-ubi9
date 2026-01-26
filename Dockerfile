FROM registry.access.redhat.com/ubi9/python-311:9.7-1769430375

LABEL maintainer="Lightning IT"
LABEL org.opencontainers.image.title="ee-wunder-ansible-ubi9"
LABEL org.opencontainers.image.description="Ansible Execution Environment (UBI 9) for Wunder automation (AAP + ansible-navigator)."
LABEL org.opencontainers.image.source="https://github.com/lightning-it/container-ee-wunder-ansible-ubi9"

ARG ANSIBLE_GALAXY_CLI_COLLECTION_OPTS=
ARG PKGMGR_OPTS="--nodocs --setopt=install_weak_deps=0 --setopt=*.module_hotfixes=1"

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
