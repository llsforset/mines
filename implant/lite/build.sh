#!/bin/sh
# Build the lite beacon inside a container (fixed linux/amd64 target).
# Usage: ./build.sh [linux|windows] [out-dir]
# Requires config.h in this directory (download from the console).
set -e
cd "$(dirname "$0")"
platform="${1:-linux}"
out="${2:-dist}"
if [ ! -f config.h ]; then
  echo "缺少 config.h：先在控制台「轻量信标」页下载，放到本目录" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "需要 docker（构建容器提供交叉编译器）" >&2
  exit 1
fi
# 固定产出 amd64：Linux 目标机是 x86_64，Windows 交叉编译本就输出 amd64 PE。
# 在 Apple Silicon 上这一步走 Rosetta/QEMU 模拟，apt 安装会慢一些，只发生一次。
docker build --platform linux/amd64 -t sliver-lite-build .
uid="$(id -u 2>/dev/null || echo 0)"
gid="$(id -g 2>/dev/null || echo 0)"
docker run --rm --platform linux/amd64 -u "$uid:$gid" -v "$PWD":/src sliver-lite-build sh compile.sh "$platform" "$out"
