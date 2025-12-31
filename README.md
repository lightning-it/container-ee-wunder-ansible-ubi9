# ee-wunder-ansible-ubi9

An **Ansible Execution Environment (EE)** based on **Red Hat UBI 9 (Python 3.11)** with **ansible-core** and **ansible-runner**, built for running playbooks via:

- **ansible-navigator** (Execution Environment mode)
- **ansible-runner** (AAP/Controller-like execution model)
- local workflows and CI pipelines

This image is intentionally minimal and deterministic: it contains only what is needed to run Ansible reliably inside a container, plus a controlled set of OS dependencies via `bindep.txt`.

> **Versioning note:** Image tags follow repository release tags (e.g. `v1.1.1`) plus `latest`.
> The Ansible version is pinned via build arguments (currently `ansible-core 2.18.x`).

---

## Image name and tags

The repository name is `container-ee-wunder-ansible-ubi9`, but the published image is:

- `ghcr.io/lightning-it/ee-wunder-ansible-ubi9:<tag>`

Example tags:
- `ghcr.io/lightning-it/ee-wunder-ansible-ubi9:v1.1.1`
- `ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest`

This image is published as **multi-arch** (linux/amd64 + linux/arm64).

---

## What’s inside

### Base
- **UBI 9** (Python 3.11 base image)

### Python tooling
- `ansible-core` **2.18.x** (pinned)
- `ansible-runner` **2.x** (pinned)

### OS dependencies
- Installed from `bindep.txt` (RPM allow-list).  
  This keeps OS dependencies explicit and reviewable.

### Ansible content
- Collections installed from `collections/requirements.yml` during build
- Optional controller collections from `collections/controller-requirements.yml` (guarded; skipped if empty)
- Optional roles from `roles/requirements.yml` (guarded; skipped if empty)

### Runtime conventions (AAP-friendly)
- Non-root runtime user: `runner` (uid/gid `1000`)
- `HOME=/runner`
- Writable layout under `/runner` and `/tmp/ansible/tmp`

---

## Filesystem layout (important for AAP / ansible-runner)

This image follows the typical Execution Environment layout expected by AAP/ansible-runner:

- `/runner/project` — project content (playbooks)
- `/runner/inventory` — inventory
- `/runner/env` — runner env (optional)
- `/runner/project/roles` and `/runner/roles` — created to avoid missing-path warnings
- `/tmp/ansible/tmp` — temp (sticky)

Environment variables are set to standardize paths:

- `ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections:/usr/share/automation-controller/collections:/runner/project/collections:/runner/collections`
- `ANSIBLE_ROLES_PATH=/usr/share/ansible/roles:/runner/project/roles:/runner/roles`

---

## Quick test (CLI)

```bash
docker run --rm ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest ansible --version
docker run --rm ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest ansible-galaxy --version
docker run --rm ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest ansible-runner --version
```

---

## AAP-like test (ansible-runner)

This closely mirrors how AAP/Controller executes jobs.

```bash
rm -rf /tmp/ee-test && mkdir -p /tmp/ee-test/project /tmp/ee-test/inventory

cat > /tmp/ee-test/project/ping.yml <<'YML'
- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.ping:
YML

cat > /tmp/ee-test/inventory/hosts <<'TXT'
localhost ansible_connection=local ansible_python_interpreter=/opt/app-root/bin/python3.11
TXT

docker run --rm -v /tmp/ee-test:/runner \
  ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest \
  bash -lc 'ansible-runner run /runner --playbook ping.yml --inventory /runner/inventory/hosts'
```

---

## Full smoke test script

A ready-to-run test script is provided to validate “AAP-like” behavior:

- `scripts/test-ee.sh`

Usage:

```bash
chmod +x scripts/test-ee.sh

# test latest
./scripts/test-ee.sh

# test a specific release tag
./scripts/test-ee.sh ghcr.io/lightning-it/ee-wunder-ansible-ubi9:v1.1.1

# test a locally built image
./scripts/test-ee.sh ee-wunder-ansible-ubi9:local
```

---

## Use with ansible-navigator

Example `ansible-navigator.yml`:

```yaml
---
ansible-navigator:
  execution-environment:
    enabled: true
    container-engine: docker
    image: ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest
    pull:
      policy: tag
    environment-variables:
      pass:
        - ANSIBLE_CONFIG
        - ANSIBLE_VAULT_PASSWORD_FILE
  mode: stdout
  playbook-artifact:
    enable: false
```

Run:

```bash
ansible-navigator run playbooks/site.yml -i inventories/prod.yml
```

---

## Build locally

```bash
docker buildx build -t ee-wunder-ansible-ubi9:local .
```

---

## Dependency updates (Renovate)

This repository uses Renovate to keep:
- `ansible-core` build arg updated (restricted to the `2.18.x` line)
- Ansible Galaxy collections in `collections/requirements.yml` updated (pinned versions)

---

## Notes

- The image uses **UBI9 Python 3.11**, aligned with modern `ansible-core` requirements.
- The image uses **CMD** (not ENTRYPOINT) to avoid command-override issues with ansible-navigator/AAP.
- Controller-specific collections and roles are **optional**; guarded install steps allow empty requirements files without breaking builds.

---

## Contributing

See `CONTRIBUTING.md`.

## Security

See `SECURITY.md`. For vulnerabilities: **security@l-it.io**.

## Code of Conduct

See `CODE_OF_CONDUCT.md`.

## License

See `LICENSE` and any upstream dependency licenses as applicable.
