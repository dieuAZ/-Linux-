#!/usr/bin/env python3
"""Make Probe reject unusable API keys and missing QEMU runtime libraries."""

from pathlib import Path

probe_root = Path("/media/iotteam/hd/pyh/mi/llm_probe")

task = probe_root / "task.py"
source = task.read_text(encoding="utf-8")
old = '''        if not key:
            raise RuntimeError("missing API key")
        api_base = str(cfg.get("api_base") or "").strip()
'''
new = '''        if not key:
            raise RuntimeError("missing API key")
        if not key.isascii():
            raise RuntimeError("OPENAI_API_KEY contains non-ASCII characters; configure a real ASCII API key")
        api_base = str(cfg.get("api_base") or "").strip()
'''
if source.count(old) != 1:
    raise SystemExit("ProbeAgent API key validation location changed")
task.write_text(source.replace(old, new), encoding="utf-8")

deep = probe_root / "agent" / "DeepCommon.py"
source = deep.read_text(encoding="utf-8")
old = '''    qemu_raw = str(result.get("qemu_log", ""))
    result["qemu_execution_log"] = _write_qemu_execution_log(
'''
new = '''    qemu_raw = str(result.get("qemu_log", ""))
    if (result.get("status") == "qemu_failed" and
            "error while loading shared libraries" in qemu_raw.lower()):
        result["fatal"] = True
    result["qemu_execution_log"] = _write_qemu_execution_log(
'''
if source.count(old) != 2:
    raise SystemExit("QEMU preflight validation location changed")
position = source.rfind(old)
deep.write_text(source[:position] + new + source[position + len(old):], encoding="utf-8")
