#!/bin/bash
set -e

IMAGE="pageguo/maxmux"
VERSION=${1:-}

if [ -z "$VERSION" ]; then
  echo "Usage: ./release.sh <version>  e.g. ./release.sh v0.4"
  exit 1
fi

echo "==> Building image for linux/amd64: $IMAGE:$VERSION"
docker build --platform linux/amd64 -t "$IMAGE:$VERSION" -t "$IMAGE:latest" .

echo "==> Pushing $IMAGE:$VERSION and $IMAGE:latest"
docker push "$IMAGE:$VERSION"
docker push "$IMAGE:latest"

echo "==> Tagging git commit as $VERSION"
git tag "$VERSION"
git push mine "$VERSION"
git push mine master

echo "==> Done: $IMAGE:$VERSION pushed to Docker Hub and git tag $VERSION pushed"
