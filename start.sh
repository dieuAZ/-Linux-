#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# QEMU's configure script compiles and runs test binaries under /tmp.
# Remount the container tmpfs with exec so those checks and builds can run.
python3 - <<'PY'
import ctypes
import os

libc = ctypes.CDLL(None, use_errno=True)
MS_REMOUNT = 32
MS_NOSUID = 2
MS_NODEV = 4
if libc.mount(None, b"/tmp", None, MS_REMOUNT | MS_NOSUID | MS_NODEV, None):
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), "/tmp")
PY
exec python3 server.py
