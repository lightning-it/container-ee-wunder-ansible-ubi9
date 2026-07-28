# ee-wunder-ansible-ubi9

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
Required test profiles: `pre-commit, lint, container-build, container-smoke, trivy, fuzzing, release-validation`.
Publishing targets: `github-release, quay.io`.

## Supported and Tested Platforms

| Platform / Product |                  Status | Validation           |
| ------------------ | ----------------------: | -------------------- |
| ubuntu-latest      |               Supported | Container CI / Trivy |
| ubi9               | Tested where applicable | Container CI / Trivy |
| podman             | Tested where applicable | Container CI / Trivy |
| docker-buildx      | Tested where applicable | Container CI / Trivy |

<!-- END LIT_SHARED_RELEASE_MODEL -->

<!-- BEGIN LIT_QUALITY_BADGES -->

[![CI](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-ci.yml/badge.svg?branch=develop)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/lightning-it/container-ee-wunder-ansible-ubi9?sort=semver)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/releases/latest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lightning-it/container-ee-wunder-ansible-ubi9/badge)](https://scorecard.dev/viewer/?uri=github.com/lightning-it/container-ee-wunder-ansible-ubi9)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13513/badge)](https://www.bestpractices.dev/projects/13513)
[![Quay.io](https://img.shields.io/badge/Quay.io-image-blue?logo=quay&logoColor=white)](https://quay.io/repository/l-it/ee-wunder-ansible-ubi9)
[![Trivy](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-trivy.yml/badge.svg?branch=develop)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-trivy.yml)
[![Container Build](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-build.yml/badge.svg?branch=develop)](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/actions/workflows/container-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

<!-- END LIT_QUALITY_BADGES -->

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

Release verification uses an isolated 4 GiB temporary workspace for the Trivy database and image scan.

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

## Security

See [SECURITY.md](./SECURITY.md) for supported versions and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution and review expectations.

## License

See [LICENSE](./LICENSE).

<!-- BEGIN LIT_RELEASE_QUALITY_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.
The README shows the current supported and tested matrix.
Exact per-version validation proof is stored with each GitHub Release as `release-evidence.md` and `release-evidence.json`.
Releases are created from the protected `main` branch after a reviewed `develop -> main` release promotion.
Container releases validate build, smoke behavior, Trivy scanning, and Quay.io publishing where enabled.

See:

- [RELEASE.md](./RELEASE.md)
- [TESTING.md](./TESTING.md)
- [GitHub Releases](../../releases)

Repository classification: **Container Image**.
Required test profiles: `pre-commit, lint, container-build, container-smoke, trivy, release-validation`.
Publishing targets: `github-release, quay.io`.

<!-- END LIT_RELEASE_QUALITY_MODEL -->

<!-- BEGIN LIT_COMPATIBILITY_MATRIX -->

## Compatibility Matrix

| Image Version | Base Image | Runtime | Validation |
|---|---|---|---|
| Latest release | ubi9 | Podman / GitHub Actions | See release evidence |
| Latest release | podman | Podman / GitHub Actions | See release evidence |
| Latest release | docker-buildx | Podman / GitHub Actions | See release evidence |

Validation proof for each released version is stored in the corresponding GitHub Release evidence.

<!-- END LIT_COMPATIBILITY_MATRIX -->

## Release Evidence

Every released version includes immutable release evidence attached to the corresponding GitHub Release.
The evidence records:

- tested matrix combinations
- GitHub Actions run links
- artifact references
- publish status
- security scan status

See [GitHub Releases](../../releases), [RELEASE.md](./RELEASE.md), and [TESTING.md](./TESTING.md) for the release process and validation model.
