#!/usr/bin/env python3
"""Bridge one HTML Probe task to the real backend llm_probe entry point."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
import urllib.request
from pathlib import Path


API = "http://127.0.0.1:8080"
SYSTEM_CONFIG = Path(__file__).resolve().parent / "config" / "system.json"


def report(task_id: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{API}/api/tasks/{task_id}/report", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10):
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--task-dir", required=True, type=Path)
    parser.add_argument("--driver", required=True)
    args = parser.parse_args()
    configs_dir = args.task_dir / "snapshot" / "configs"
    log_path = args.task_dir / "logs" / "workflow.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    report(args.task_id, {"stage": "PROBE", "status": "RUNNING",
                          "message": f"启动后台 Probe：{args.driver}"})
    task_meta = json.loads((args.task_dir / "snapshot" / "task.json").read_text(encoding="utf-8"))
    extra_enabled = bool(task_meta.get("extra_enabled", False))
    settings = json.loads(SYSTEM_CONFIG.read_text(encoding="utf-8"))
    backend = settings.get("backend", {})
    runner = backend.get("probe_runner", [])
    if not runner:
        raise RuntimeError("config/system.json 缺少 backend.probe_runner")
    cwd = Path(backend.get("root", "/media/iotteam/hd/pyh/mi"))
    modes = ["static", "deep"] + (["extra"] if extra_enabled else [])
    mode_status = {}
    child_env = os.environ.copy()
    child_env["PYTHONUNBUFFERED"] = "1"
    with log_path.open("ab", buffering=0) as output:
        for mode in modes:
            mode_config = configs_dir / f"probe_{mode}.json"
            if mode == "extra":
                mode_config = configs_dir / "probe_deep.json"
            if not mode_config.is_file():
                raise RuntimeError(f"缺少 Probe 配置：{mode_config}")
            replacements = {
                "{probe_mode}": mode,
                "{probe_config}": str(mode_config),
                "{driver}": args.driver,
            }
            command = [str(part) for part in runner]
            for index, part in enumerate(command):
                for key, value in replacements.items():
                    command[index] = command[index].replace(key, value)
            if command[0] == "python3":
                command[0] = sys.executable
            output.write(
                f"\n===== Probe {mode} START {datetime.now().astimezone().isoformat(timespec='seconds')} =====\n"
                f"$ {' '.join(command)}\n".encode("utf-8")
            )
            output.flush()
            report(args.task_id, {"stage": "PROBE", "status": "RUNNING",
                                  "probe_modes": mode_status,
                                  "message": f"执行 Probe {mode}：{args.driver}"})
            process = subprocess.run(command, cwd=str(cwd), stdout=output,
                                     stderr=subprocess.STDOUT, env=child_env, check=False)
            mode_status[mode] = {"status": "PASSED" if process.returncode == 0 else "FAILED"}
            output.write(
                f"===== Probe {mode} END {datetime.now().astimezone().isoformat(timespec='seconds')} "
                f"status={process.returncode} =====\n".encode("utf-8")
            )
            output.flush()
            if process.returncode != 0:
                report(args.task_id, {
                    "stage": "PROBE", "status": "FAILED",
                    "probe_modes": mode_status,
                    "message": f"Probe {mode} 失败，返回码 {process.returncode}",
                })
                return process.returncode or 1
    if all(value["status"] == "PASSED" for value in mode_status.values()):
        report(args.task_id, {
            "stage": "PROBE", "status": "COMPLETED",
            "probe_modes": {mode: {**value, "content": {}} for mode, value in mode_status.items()},
            "message": "后台 Probe 完成；QEMU/设备验证结果已写入 workflow.log。",
        })
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
