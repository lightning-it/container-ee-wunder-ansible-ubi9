# ee-wunder-ansible-ubi9

An **Ansible Execution Environment (EE)** based on **Red Hat UBI 9** with **ansible-core**, built for running playbooks via **ansible-navigator** (Execution Environment mode) in local workflows and CI.

This image is intentionally minimal: it provides only the tooling required to run Ansible reliably inside a container (plus common utilities like SSH client and rsync).

---

## What’s inside

- UBI 9 (Python 3.11 base)
- `ansible-core` **2.18.x**
- Common CLI utilities required by typical playbooks:
  - `bash`, `git`, `openssh-clients`, `rsync`, `tar`, `unzip`, `which`, `findutils`, `ca-certificates`
- Non-root runtime user: `wunder`
- Writable `HOME` + Ansible temp dirs (prevents `/.ansible` permission issues)

---

## Build

```bash
docker build \
  -t ghcr.io/lightning-it/ee-wunder-ansible-ubi9:v2.18.0 \
  --build-arg ANSIBLE_CORE_VERSION=2.18.0 \
  .
```

## Test

```bash
docker run --rm ghcr.io/lightning-it/ee-wunder-ansible-ubi9:v2.18.0 \
  ansible --version

docker run --rm ghcr.io/lightning-it/ee-wunder-ansible-ubi9:v2.18.0 \
  ansible-galaxy --version
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
    image: ghcr.io/lightning-it/ee-wunder-ansible-ubi9:v2.18.0
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

## Notes

- This image uses **UBI9 Python 3.11**, because **ansible-core 2.18 requires Python 3.11+**.
- Use **CMD** (not ENTRYPOINT) to avoid command-override issues when ansible-navigator executes commands inside the container.

---

## License

See the repository license and any upstream dependency licenses as applicable.
