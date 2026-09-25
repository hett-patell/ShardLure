# Releasing ShardLure

Releases are triggered by an annotated version tag. First merge the release changes and push `main`:

```bash
git switch main
git pull --ff-only origin main
git push origin main
```

Create and push the annotated tag, replacing `v2.0.0` with the release version when needed:

```bash
git tag -a v2.0.0 -m 'ShardLure v2.0.0'
git push origin refs/tags/v2.0.0
```

The tag's CI run must pass the disposable Ubuntu installer integration (`.github/workflows/installer-integration.yml`) as well as the cross-builds: the release job depends on both, so an installer regression blocks publication instead of shipping.

CI owns the rest of the release transaction. It builds and smoke-tests every target, generates `SHA256SUMS`, creates or reuses a draft release, uploads all assets, and publishes only after the upload succeeds. If a build or upload fails, CI does not publish the release.
