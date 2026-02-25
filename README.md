# ee-wunder-ansible-ubi9

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
