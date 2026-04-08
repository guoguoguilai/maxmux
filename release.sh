#!/bin/bash
set -e

IMAGE="pageguo/maxmux"
VERSION=$(grep -oP 'var version = "\K[^"]+' main.go)

if [ -z "$VERSION" ]; then
  echo "Error: could not read version from main.go"
  exit 1
fi

echo "==> Version from main.go: $VERSION"
echo "==> Building image for linux/amd64: $IMAGE:$VERSION"
docker buildx build --platform linux/amd64 -t "$IMAGE:$VERSION" -t "$IMAGE:latest" .

echo "==> Pushing $IMAGE:$VERSION and $IMAGE:latest"
docker push "$IMAGE:$VERSION"
docker push "$IMAGE:latest"

echo "==> Pushing code to remote"
git push mine master

echo "==> Done: $IMAGE:$VERSION pushed to Docker Hub"
