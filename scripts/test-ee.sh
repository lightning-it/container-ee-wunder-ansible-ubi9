#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-ghcr.io/lightning-it/ee-wunder-ansible-ubi9:latest}"

echo "==> Testing EE image: ${IMAGE}"
echo

# --- 0) Basic pull (optional, comment out if you only test local images)
echo "==> Pull (best effort)"
docker pull "${IMAGE}" >/dev/null 2>&1 || true
echo

# --- 1) Basic info
echo "==> Basic runtime info"
docker run --rm "${IMAGE}" bash -lc '
  set -euo pipefail
  echo "whoami: $(whoami)"
  echo "id:     $(id)"
  python -V
  ansible --version
  ansible-galaxy --version
  ansible-runner --version
  echo "HOME=$HOME"
'
echo

# --- 2) Runner layout + permissions
echo "==> Runner layout / permissions"
docker run --rm "${IMAGE}" bash -lc '
  set -euo pipefail
  test -d /runner/project
  test -d /runner/inventory
  test -d /runner/env
  test -d /runner/project/roles
  test -d /runner/roles
  test -w /runner
  test -w /tmp/ansible/tmp
  ls -ld /runner /runner/project /runner/project/roles /runner/roles /runner/inventory /runner/env /tmp/ansible /tmp/ansible/tmp
  echo "runner layout OK"
'
echo

# --- 3) Collections & roles paths
echo "==> Collections & roles paths"
docker run --rm "${IMAGE}" bash -lc '
  set -euo pipefail
  echo "ANSIBLE_COLLECTIONS_PATH=$ANSIBLE_COLLECTIONS_PATH"
  echo "ANSIBLE_ROLES_PATH=$ANSIBLE_ROLES_PATH"
  echo
  echo "Collections (top):"
  ansible-galaxy collection list | head -n 60
  echo
  echo "Roles (system path):"
  ansible-galaxy role list -p /usr/share/ansible/roles || true
'
echo

# --- 4) AAP-like runner execution
echo "==> ansible-runner execution test (AAP-like)"
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "${TMPDIR}"; }
trap cleanup EXIT

mkdir -p "${TMPDIR}/project" "${TMPDIR}/inventory"

cat > "${TMPDIR}/project/ping.yml" <<'YML'
- hosts: localhost
  gather_facts: false
  tasks:
    - name: ping
      ansible.builtin.ping:
YML

# pin interpreter to avoid discovery warning noise
cat > "${TMPDIR}/inventory/hosts" <<'TXT'
localhost ansible_connection=local ansible_python_interpreter=/opt/app-root/bin/python3.11
TXT

docker run --rm \
  -v "${TMPDIR}:/runner" \
  "${IMAGE}" \
  bash -lc '
    set -euo pipefail
    ansible-runner run /runner \
      --playbook ping.yml \
      --inventory /runner/inventory/hosts \
      --json \
    | tail -n 50
  '
echo

# --- 5) Write test to /runner/.ansible/tmp
echo "==> Write test (/runner/.ansible/tmp)"
docker run --rm "${IMAGE}" bash -lc '
  set -euo pipefail
  python - <<PY
from pathlib import Path
p = Path("/runner/.ansible/tmp")
p.mkdir(parents=True, exist_ok=True)
(p / "test.txt").write_text("ok", encoding="utf-8")
print("write ok:", (p / "test.txt").read_text(encoding="utf-8").strip())
PY
'
echo

echo "✅ All EE tests passed for: ${IMAGE}"
