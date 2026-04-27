---
name: release-image
description: "Build and push Docker images with version tag bumping for the maxmux project. Use this skill when the user wants to release a new version, bump a version tag, build and push a Docker image, or do a release. Trigger phrases include: 'release', 'bump version', 'push image', 'build image', 'tag and push', 'new version', 'deploy image', 'release image', '发版', '发布', '打包', '推送镜像', '改tag', '升级版本'."
---

# Release Image

One-shot release workflow: bump version, commit everything, build Docker image, push to registry and remote. Designed to run with minimal user interaction — the user says "发版" and it happens.

## Version source

The version lives in `main.go` as:
```go
var version = "vX.Y.Z"
```

## Workflow

### 1. Read current state

In parallel:
- Grep `main.go` for `^var version = ` to get the current version
- Run `git status --short` to see all pending changes
- Run `git diff --stat` to get a quick summary of what changed

### 2. Determine new version

- If the user provided an explicit version (e.g. "发版 v0.7.0"), use it.
- If the user said "minor" or "major", bump accordingly.
- Otherwise, **auto-patch-bump** (v0.6.1 → v0.6.2). This is the default — no need to ask.

### 3. Update version and commit

Edit the `var version` line in `main.go`, then stage **all** modified tracked files plus the version change. Do NOT ask the user whether to include other changes — if they're working on this branch and said "发版", they want everything committed.

Commit message format based on what changed:
- If there are meaningful code changes beyond the version bump, write a descriptive message summarizing them, with the version in parentheses at the end. Example: `Add token edit support, fix cost calculation timezone (v0.6.2)`
- If the only change is the version bump itself: `Bump version to v0.6.2`

Include the Co-Authored-By trailer.

### 4. Build, push image, push code

The project has a `release.sh` that handles the build and push pipeline. Run it:

```bash
bash release.sh
```

This script:
1. Reads the version from `main.go`
2. Builds `pageguo/maxmux:$VERSION` and `pageguo/maxmux:latest` via `docker buildx` (linux/amd64)
3. Pushes both tags to Docker Hub
4. Pushes code to `mine master`

Run with `run_in_background` since the Docker build takes time. Report progress when it completes.

### 5. Summary

Print a compact summary:
```
v0.6.1 → v0.6.2
Image: pageguo/maxmux:v0.6.2 + latest
```

## Error handling

- **docker buildx fails**: Check if a builder exists (`docker buildx ls`). If not, suggest `docker buildx create --use`.
- **git push fails**: Show the error, let the user decide.
- **Version not found in main.go**: Stop and report.

## Important notes

- The remote is `mine`, the branch is `master`. This is hardcoded in `release.sh`.
- Always use `release.sh` rather than running docker/git commands manually — it's the source of truth for the build pipeline.
- Do NOT ask for confirmation before pushing. The user invoked "发版" which means "do the release". If they wanted to review first, they would have said so. The only interaction point is if something fails.
