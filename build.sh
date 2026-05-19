#!/usr/bin/env bash
set -euo pipefail

MODULE=$(go list -m)
BINARY=$(basename "$MODULE")
OUT=dist

mkdir -p "$OUT"

build() {
  local goos=$1 goarch=$2 name=$3
  echo "building $OUT/$name (GOOS=$goos GOARCH=$goarch)"
  GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$OUT/$name" .
}

build darwin  arm64  "${BINARY}-mac-arm64"
build darwin  amd64  "${BINARY}-mac-amd64"
build linux   amd64  "${BINARY}-linux"
build windows amd64  "${BINARY}-windows.exe"

# cc-vpn-check-mac 指向 arm64（现代 Mac 默认）
cp "$OUT/${BINARY}-mac-arm64" "$OUT/${BINARY}-mac"

echo "done — outputs in $OUT/"
ls -lh "$OUT/"
