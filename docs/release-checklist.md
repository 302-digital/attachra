# Release checklist (SemVer, tag on staging)

Version ladder: v0.0.x — dev snapshots; v0.1.0 — first end-to-end mail path
(end of M1); v1.0.0 — public stability of formats. The tag is set by a human
or by the orchestrator with the founder's sign-off (internal process docs).

## Before tagging

1. `dev` is green: the latest pipeline on `dev` passed (build-test, lint,
   cross-compile — all required jobs).
2. CHANGELOG.md has a section for the new version (stories/features,
   infrastructure).
3. The `dev → staging` MR is created and merged on green CI (promotion of
   already-reviewed commits).
4. The pipeline on `staging` is green, including `build-image`
   (image `<container-registry>/attachra:staging`).
5. Open Critical tickets for the release are checked: nothing in the
   version's scope is left In Progress.

## Tagging

6. The tag is set on the `staging` merge commit:
   `git tag v0.X.Y <staging-sha> && git push origin v0.X.Y`.
   Format must strictly be `vMAJOR.MINOR.PATCH` (regex in the CI config:
   `^v\d+\.\d+\.\d+$`).

## After tagging

7. CI on the tag builds and pushes images
   `<container-registry>/attachra:vX.Y.Z` and `:vX.Y.Z-<short-sha>` — check
   that the tag pipeline's `build-image` job is green.
8. Check the binary version from the image or a local build:
   `make build && ./attachra --version` → prints vX.Y.Z
   (the version comes from `git describe --tags` via LDFLAGS, since the tag
   sits on the `staging` commit, which is an ancestor of the commit under
   test — the tag is "reachable"). On `dev`/feature branches the tag is
   usually unreachable (tags are only set on `staging`): in that case the
   `Makefile` falls back to the repository's latest semver tag without
   requiring reachability and builds the version as
   `vX.Y.Z+git.<shortsha>[.dirty]` — compatible with dpkg version comparison
   (`make build-deb`), unlike the previous fallback to a bare SHA, which on
   some hashes compared as "greater than" the real release and broke `.deb`
   package upgrades.
9. Check that the tag pipeline's `build-deb` job is green: it runs
   `make build-deb`, producing `dist/attachra_<version>_amd64.deb` and
   `dist/attachra_<version>_arm64.deb`, then publishes both plus a
   `SHA256SUMS` manifest to the GitLab generic package registry — no manual
   upload step. On a tag build `<version>` is the clean `X.Y.Z` (see step 8),
   so the packages land at:
   `<gitlab-instance>/api/v4/projects/<project-id>/packages/generic/attachra/X.Y.Z/attachra_X.Y.Z_amd64.deb`
   (and `..._arm64.deb`, `.../SHA256SUMS`) — browsable under the project's
   Packages & Registries → Package Registry page.
10. Update the status snapshot in the internal project notes and the comment
    on the release ticket (what shipped, links to the pipeline/image/deb
    packages).
