# REP-60 protected main bootstrap provenance

This change promotes an already protected Shared Assets generation from
`develop` to `main`; it does not edit a Shared Assets managed file downstream.

The generation was produced from `lightning-it/shared-assets-lit` commit
`3a32e8d0ab32edb0956f7a8cf3fc8c001e583497` by run `33802454852`, committed by
the Shared Assets Sync App as
`5a2b07051eed10e401df421eee866e1a3dbcbeeb`, and merged normally through PR
[#800](https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/pull/800)
as protected `develop` commit
`35582d4a2625219f620330ef9b70475958cadfc5`.

The six promoted files, including `renovate.json`, are byte-identical to that
protected `develop` generation. Keeping `renovate.json` in the same change is
required because it carries the Renovate package rules and custom managers for
the newly source-built, pinned Terraform, Terragrunt, and Helm toolchain.

This bounded bootstrap is necessary because the older `main` controller cannot
yet dispatch the protected exact-revision review workflow. It creates no new
review exception, bypass, or downstream ownership rule. Subsequent changes to
these managed files continue to originate exclusively in Shared Assets and
arrive through the official sync path.

## Exact-revision controller dependency closure

The follow-up bootstrap copies the complete protected exact-revision review
dependency set from the same protected `develop` commit: the current-revision
dispatcher/verifier, the Exact-Revision Codex dispatch controller, the protected
rerun helper, the Git-object materializer, the review prompt, and the strict
result schema. All six files are byte-identical to the official Shared Assets
generation identified above; none is edited downstream.

The six files move together because the current-revision controller must
dispatch and verify the exact workflow contract that its protected Codex
controller implements, and that controller is not usable without its rerun
helper, materializer, prompt, and schema. Once this dependency closure is present
on protected `main`, ordinary same-repository Release App pull requests can use
the MLX-90 section 7.2 exact-revision Codex path. This bootstrap does not
authorize an additional AI request, a retry, a bypass, a force-push, or a new
exception.
