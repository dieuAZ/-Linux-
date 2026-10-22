#!/usr/bin/env python3
"""Execute one static-analysis task from its expanded task configuration."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def report(task_id: str, payload: dict) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:8080/api/tasks/{task_id}/report",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10):
        pass


def run(cmd: list[str], env: dict[str, str], log, cwd: Path | None = None) -> None:
    print("$ " + " ".join(cmd), file=log, flush=True)
    completed = subprocess.run(cmd, env=env, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise RuntimeError(f"命令失败({completed.returncode})：{cmd[0]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--task-dir", required=True)
    args = parser.parse_args()
    task_dir = Path(args.task_dir).resolve()
    task_cfg_path = task_dir / "snapshot" / "configs" / "static_analysis.json"
    task_cfg = json.loads(task_cfg_path.read_text(encoding="utf-8"))
    output_dir = Path(task_cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = task_dir / "logs" / "workflow.log"

    env = os.environ.copy()
    env.update({str(k): str(v) for k, v in task_cfg.get("environment", {}).items() if k != "PATH_PREFIX"})
    prefix = task_cfg.get("environment", {}).get("PATH_PREFIX")
    if prefix:
        env["PATH"] = str(prefix) + os.pathsep + env.get("PATH", "")
    tools = task_cfg["tools"]
    python = sys.executable
    with log_path.open("a", encoding="utf-8") as log:
        try:
            report(args.task_id, {"stage": "MERGING_BITCODE", "status": "RUNNING", "static_analysis": {"merge": {"status": "RUNNING"}}})
            run([python, tools["bitcode_merger"], "--config", str(Path(__file__).parent / "config" / "static_analysis_params.json"),
                 "--linux", task_cfg["linux"], "--driver", task_cfg["driver"], "--output", task_cfg["merged_bitcode"]], env, log)
            merged = Path(task_cfg["merged_bitcode"])
            collector_input = Path(task_cfg["collector_input_dir"])
            collector_stage = None
            if collector_input.is_file():
                collector_stage = Path(tempfile.mkdtemp(prefix=f"{task_cfg['driver']}_collector_"))
                target = collector_stage / merged.name
                shutil.copy2(merged, target)
                collector_input_arg = collector_stage
            else:
                collector_input.mkdir(parents=True, exist_ok=True)
                target = collector_input / merged.name
                if target.exists() or target.is_symlink():
                    target.unlink()
                shutil.copy2(merged, target)
                collector_input_arg = collector_input
            analysis_dir = Path(task_cfg["analysis_dir"])
            analysis_dir.mkdir(parents=True, exist_ok=True)
            generated_entry = merged.parent / f"{task_cfg['driver']}_entries.conf"
            entry_config = Path(task_cfg["entry_config"])
            if generated_entry.exists() and generated_entry.resolve() != entry_config.resolve():
                shutil.copy2(generated_entry, entry_config)
            if not entry_config.exists():
                raise RuntimeError(f"没有生成入口配置：{entry_config}")

            report(args.task_id, {"stage": "COLLECTOR", "status": "RUNNING", "static_analysis": {"merge": {"status": "PASSED", "output": str(merged)}, "collector": {"status": "RUNNING"}}})
            try:
                run(["bash", tools["collector"], str(collector_input_arg), task_cfg["collector_log"], task_cfg["vmlinux"], task_cfg["output_dir"]], env, log)
            finally:
                if collector_stage:
                    shutil.rmtree(collector_stage, ignore_errors=True)
            report(args.task_id, {"stage": "BACKWARD_ANALYSIS", "status": "RUNNING", "static_analysis": {"collector": {"status": "PASSED"}, "svf": {"status": "RUNNING"}}})
            run([python, tools["backward_analyzer"], "--mode", "build-index", "--bitcode", str(merged), "--entry-config", str(entry_config),
                 "--output-dir", task_cfg["analysis_dir"], "--index-dir", task_cfg["index_dir"], "--svf-root", tools["svf_root"],
                 "--svf-build", tools["svf_build"], "--svf-analyzer", tools["svf_analyzer"], "--emit-intermediate"], env, log, Path(tools["backward_analyzer"]).parent)
            report(args.task_id, {"stage": "DRIVER_FIX", "status": "RUNNING", "static_analysis": {"collector": {"status": "PASSED"}, "svf": {"status": "PASSED"}, "driver_fix": {"status": "RUNNING"}}})
            driver_fix_dir = Path(task_cfg["driver_fix_dir"])
            driver_fix_dir.mkdir(parents=True, exist_ok=True)
            entry = task_cfg.get("probe_entry_function", "")
            if not entry:
                entries = task_cfg.get("probe_entry_functions", [])
                entry = entries[0] if entries else ""
            if not entry:
                raise RuntimeError("静态分析目标没有配置 probe 入口函数")
            driver_fix_merged = Path(task_cfg["driver_fix_bitcode"])
            driver_fix_merged.parent.mkdir(parents=True, exist_ok=True)
            run([python, tools["bitcode_merger"], "--config", str(Path(__file__).parent / "config" / "static_analysis_params.json"),
                 "--linux", task_cfg["linux"], "--driver", task_cfg["driver"], "--input-set", "driver_fix",
                 "--output", str(driver_fix_merged)], env, log)
            driver_fix_stage = Path(tempfile.mkdtemp(prefix=f"{task_cfg['driver']}_driver_fix_"))
            staged_driver_fix = driver_fix_stage / driver_fix_merged.name
            shutil.copy2(driver_fix_merged, staged_driver_fix)
            try:
                run([python, tools["svf_find_sv_alias"], tools["wpa"], str(driver_fix_stage), "--entry", entry, "--outdir", str(driver_fix_dir)], env, log)
            finally:
                shutil.rmtree(driver_fix_stage, ignore_errors=True)
            callgraph = driver_fix_dir / f"{driver_fix_merged.name}.callgraph_final.dot"
            if not callgraph.is_file():
                raise RuntimeError(f"svf_find_sv_alias 未生成调用图：{callgraph}")
            run([python, tools["extract_functions"], "--callgraph", str(callgraph), "--outdir", str(driver_fix_dir), "--driver", task_cfg["driver"], entry], env, log)
            source_root = Path(task_cfg["source_root"])
            source_base = source_root / "drivers"
            impl_roots = [str((source_base / rel).resolve()) for rel in task_cfg["driver_config"].get("source_rel", [])]
            mmio_config = task_dir / "snapshot" / "configs" / "driver_fix_mmio.json"
            mmio_config.write_text(json.dumps({"dir": str(driver_fix_dir), "driver": task_cfg["driver"], "impl_root": impl_roots}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            run([python, tools["generate_mmio_arrays"], str(mmio_config)], env, log)
            report(args.task_id, {"stage": "FINISHED", "status": "COMPLETED", "static_analysis": {"collector": {"status": "PASSED"}, "svf": {"status": "PASSED"}, "driver_fix": {"status": "PASSED"}}})
            return 0
        except Exception as exc:
            print(f"static analysis failed: {exc}", file=log, flush=True)
            try:
                report(args.task_id, {"stage": "FAILED", "status": "FAILED", "message": str(exc), "static_analysis": {"status": "FAILED"}})
            except Exception as report_exc:
                print(f"report failed: {report_exc}", file=log, flush=True)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
