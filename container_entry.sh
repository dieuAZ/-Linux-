#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Preserve the existing image's /tmp remount behavior for QEMU configure.
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
