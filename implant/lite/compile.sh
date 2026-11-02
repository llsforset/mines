#!/bin/sh
# in-container compiler entrypoint: compile.sh <linux|windows> <out-dir>
set -e
cd /src
platform="${1:-linux}"
out="${2:-dist}"
mkdir -p "$out"
case "$platform" in
  linux)
    gcc -Os -s -fno-ident -fno-asynchronous-unwind-tables -o "$out/lite" main.c linux.c -lssl -lcrypto
    ;;
  windows)
    x86_64-w64-mingw32-gcc -Os -s -static -fno-ident -fno-asynchronous-unwind-tables \
      -o "$out/lite.exe" main.c win.c -lwinhttp -lbcrypt -ladvapi32
    ;;
  *)
    echo "unknown platform: $platform" >&2
    exit 1
    ;;
esac
ls -la "$out"
