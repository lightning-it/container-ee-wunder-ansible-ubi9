# MLX-90 immutable release reissue

The `v1.24.1` release was published before GitHub Release Immutability was
enabled for this repository. GitHub does not apply that setting retroactively,
so the published release remains mutable and cannot satisfy the MLX-90 final
acceptance contract.

The next patch release is therefore the first eligible immutable MLX-90
container release. It must be created by the normal `develop` to `main`
promotion and App-authenticated semantic-release path. The release workflow
must verify the repository setting before mutation and the concrete release's
immutable state before tag promotion or downstream finalization.

`v1.24.1` remains available as historical evidence, but it is explicitly not
the immutable final-acceptance release.
