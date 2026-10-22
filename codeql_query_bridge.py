#!/usr/bin/env python3
"""Bridge one CodeQL query task into the workbench report protocol."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


API = "http://127.0.0.1:8080"
ALL_QUERIES = ("irq", "hrtimer", "kthread", "napi", "rcu", "tasklet", "timer", "workqueue", "ops")


def report(task_id: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{API}/api/tasks/{task_id}/report",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10):
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--task-dir", required=True, type=Path)
    args = parser.parse_args()

    task_dir = args.task_dir.resolve()
    status_path = task_dir / "artifacts" / "codeql" / "status.json"
    config_path = task_dir / "snapshot" / "configs" / "static_query.json"
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        selected = config.get("queries")
        if not isinstance(selected, list):
            selected = []
        config["queries"] = list(dict.fromkeys([str(item).strip().lower() for item in selected] + list(ALL_QUERIES)))
        config["llm_review"] = True
        config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    runner = Path(__file__).resolve().parent / "codeql_query" / "parallel_codeql_runner.py"
    command = [
        sys.executable,
        str(runner),
        "--task-id",
        args.task_id,
        "--task-dir",
        str(task_dir),
    ]
    process = subprocess.Popen(command)
    last_status = ""
    while process.poll() is None:
        if status_path.is_file():
            try:
                value = json.loads(status_path.read_text(encoding="utf-8"))
                encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
                if encoded != last_status:
                    report(args.task_id, {
                        "stage": value.get("stage", "CODEQL_QUERY"),
                        "status": value.get("status", "RUNNING"),
                        "message": value.get("message", ""),
                        "codeql_query": value,
                    })
                    last_status = encoded
            except (OSError, json.JSONDecodeError, urllib.error.URLError):
                pass
        time.sleep(1)

    code = process.wait()
    reviewed = task_dir / "artifacts" / "codeql" / "triage_results.csv"
    legacy_result = task_dir / "artifacts" / "codeql" / "merged_semantic_unique.csv"
    if reviewed.is_file():
        shutil.copyfile(reviewed, legacy_result)
    if status_path.is_file():
        try:
            value = json.loads(status_path.read_text(encoding="utf-8"))
            report(args.task_id, {
                "stage": value.get("stage", "FINISHED"),
                "status": value.get("status", "COMPLETED" if code == 0 else "FAILED"),
                "message": value.get("message", ""),
                "codeql_query": value,
            })
        except (OSError, json.JSONDecodeError, urllib.error.URLError):
            pass
    return code


if __name__ == "__main__":
    raise SystemExit(main())
