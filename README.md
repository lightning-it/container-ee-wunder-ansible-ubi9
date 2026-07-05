# ee-wunder-ansible-ubi9

<!-- BEGIN LIT_QUALITY_BADGES -->

[![CI](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-ci.yml/badge.svg?branch=develop)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/lightning-it/container-ee-wunder-ansible-ubi9?sort=semver)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/releases/latest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lightning-it/container-ee-wunder-ansible-ubi9/badge)](https://scorecard.dev/viewer/?uri=github.com/lightning-it/container-ee-wunder-ansible-ubi9)
[![Quay.io](https://quay.io/repository/l-it/ee-wunder-ansible-ubi9/status)](https://quay.io/repository/l-it/ee-wunder-ansible-ubi9)
[![Trivy](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-build-publish.yml/badge.svg?branch=main)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-build-publish.yml)
[![Container Build](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-build-publish.yml/badge.svg?branch=main)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-build-publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

<!-- END LIT_QUALITY_BADGES -->

<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.

See [RELEASE.md](./RELEASE.md) for:

- branch and release flow
- required quality checks
- test matrix
- release evidence
- artifact publishing
- supported repository-specific release behavior

Repository classification: **Container Image**.
Required test profiles: `pre-commit, lint, container-build, container-smoke, trivy, release-validation`.
Publishing targets: `github-release, quay.io`.

## Supported and Tested Platforms

| Platform / Product | Status | Validation |
|---|---:|---|
| ubuntu-latest | Supported | Container CI / Trivy |
| ubi9 | Tested where applicable | Container CI / Trivy |
| podman | Tested where applicable | Container CI / Trivy |
| docker-buildx | Tested where applicable | Container CI / Trivy |

<!-- END LIT_SHARED_RELEASE_MODEL -->

Ansible Execution Environment (UBI 9, Python 3.11) with a multi-profile publish model:

- `ee-wunder-ansible-ubi9`: public Galaxy content profile
- `ee-wunder-ansible-ubi9-certified`: Automation Hub-certified profile baked at build time
- `ee-wunder-ansible-ubi9-bootstrap`: no collections baked in (AAP installs required collections at runtime)

## Published images

From this single repository, release CI publishes:

- `quay.io/<QUAY_NAMESPACE>/ee-wunder-ansible-ubi9:<tag>`
- `quay.io/<QUAY_NAMESPACE>/ee-wunder-ansible-ubi9:latest`
- `quay.io/<QUAY_NAMESPACE>/ee-wunder-ansible-ubi9-certified:<tag>`
- `quay.io/<QUAY_NAMESPACE>/ee-wunder-ansible-ubi9-certified:latest`
- `quay.io/<QUAY_NAMESPACE>/ee-wunder-ansible-ubi9-bootstrap:<tag>`
- `quay.io/<QUAY_NAMESPACE>/ee-wunder-ansible-ubi9-bootstrap:latest`

## Collection profiles

Build argument:

- `COLLECTION_PROFILE=public|certified|bootstrap`

Profile sources:

- `collections/requirements-base.yml` (installed for `public` and `certified`)
- `collections/requirements-certified-extra.yml` (installed only for `certified`)
- `collections/controller-requirements.yml` (optional, guarded)

### `public` profile

- Installs `requirements-base.yml`
- Uses public Galaxy collections only
- Does not require Automation Hub token

### `certified` profile

- Installs `requirements-base.yml` and `requirements-certified-extra.yml`
- Adds official RH/AAP collections
- Requires BuildKit secret `rh_automation_hub_token`
- CI injects secret from `RH_AUTOMATION_HUB_TOKEN`

### `bootstrap` profile

- Installs no Ansible collections in the image
- Intended for AAP-managed environments where collections are installed by AAP at runtime
- Does not require Automation Hub token during image build

## CI publish flow

Workflow: `.github/workflows/container-build-publish.yml`

Trigger:

- GitHub Release `published`

Required repository configuration:

- Variable: `QUAY_NAMESPACE`
- Secrets: `QUAY_USERNAME`, `QUAY_PASSWORD`
- Secret for certified profile build: `RH_AUTOMATION_HUB_TOKEN`

## Local builds

Public image:

```bash
docker buildx build \
  --build-arg COLLECTION_PROFILE=public \
  -t ee-wunder-ansible-ubi9:public-local \
  .
```

Certified image:

```bash
export RH_AUTOMATION_HUB_TOKEN='<token>'

docker buildx build \
  --build-arg COLLECTION_PROFILE=certified \
  --secret id=rh_automation_hub_token,env=RH_AUTOMATION_HUB_TOKEN \
  -t ee-wunder-ansible-ubi9-certified:local \
  .
```

Bootstrap image (no collections):

```bash
docker buildx build \
  --build-arg COLLECTION_PROFILE=bootstrap \
  -t ee-wunder-ansible-ubi9-bootstrap:local \
  .
```

## Smoke test

```bash
./scripts/test-ee.sh ee-wunder-ansible-ubi9:public-local
./scripts/test-ee.sh ee-wunder-ansible-ubi9-certified:local
./scripts/test-ee.sh ee-wunder-ansible-ubi9-bootstrap:local
```

## Runtime note

For disconnected execution, preload/mirror the selected EE image and use it explicitly in runtime wrappers (for example `ANSIBLE_TOOLBOX_NAV_EE_IMAGE=<image:tag>`).
