#!/usr/bin/env python3
"""Merge the configured driver and framework LLVM bitcode inputs."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


def load_driver(config_path: Path, linux: str, driver: str) -> tuple[dict, dict]:
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    entries = raw if isinstance(raw, list) else [raw]
    for item in entries:
        value = item.get(linux) if isinstance(item, dict) else None
        if not isinstance(value, dict):
            continue
        for entry in value.get("drivers", []):
            if isinstance(entry, dict) and entry.get("name") == driver:
                return value, entry
    raise ValueError(f"未找到静态分析目标：{linux}/{driver}")


def collect_inputs(root: Path, linux_config: dict, driver_config: dict, input_set: str = "analysis") -> list[Path]:
    if input_set == "driver_fix":
        dir_key = "driver_fix_bitcode_dirs"
        file_key = "driver_fix_bitcode_files"
    else:
        dir_key = "bitcode_dirs"
        file_key = "bitcode_files"
    inputs: list[Path] = []
    configured_dirs = driver_config.get(dir_key)
    configured_files = driver_config.get(file_key)
    if configured_dirs is None and configured_files is None:
        configured_dirs = driver_config.get("bitcode_dirs", [])
        configured_files = driver_config.get("bitcode_files", [])
    def append_existing(dirs: list, files: list) -> None:
        for rel_dir in dirs or []:
            directory = (root / str(rel_dir)).resolve()
            if directory.is_dir():
                inputs.extend(sorted(directory.rglob("*.bc")))
        for rel_file in files or []:
            path = (root / str(rel_file)).resolve()
            if path.is_file():
                inputs.append(path)

    append_existing(configured_dirs, configured_files)
    if input_set == "driver_fix" and not inputs:
        append_existing(driver_config.get("bitcode_dirs", []),
                        driver_config.get("bitcode_files", []))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in inputs:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    if not unique:
        raise ValueError(f"没有为目标配置 bitcode 输入：{driver_config.get('name')}")
    return unique


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/static_analysis_params.json")
    parser.add_argument("--linux", required=True)
    parser.add_argument("--driver", required=True)
    parser.add_argument("--output", help="override configured merged_bitcode path")
    parser.add_argument("--input-set", choices=("analysis", "driver_fix"), default="analysis")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    linux_config, driver_config = load_driver(config_path, args.linux, args.driver)
    root = Path(linux_config["bitcode_root"]).resolve()
    inputs = collect_inputs(root, linux_config, driver_config, args.input_set)
    output_value = args.output or driver_config.get("merged_bitcode")
    if not output_value:
        raise ValueError("配置缺少 merged_bitcode")
    output = Path(str(output_value))
    if not output.is_absolute():
        output_root = Path(str(linux_config.get("merged_output_root", root))).resolve()
        output = (output_root / output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output in inputs:
        raise ValueError("合并产物不能同时作为输入 bitcode")

    linker = os.environ.get("LLVM_LINK")
    if linker and not Path(linker).is_file():
        raise FileNotFoundError(f"LLVM_LINK 不存在：{linker}")
    linker = linker or shutil.which("llvm-link-15") or shutil.which("llvm-link")
    if not linker:
        raise RuntimeError("找不到 llvm-link-15 或 llvm-link")

    subprocess.run([linker, *map(str, inputs), "-o", str(output)], check=True)
    entry_config = None
    points = list(driver_config.get("entry_points", [])) if args.input_set == "analysis" else []
    if args.input_set == "analysis":
        points.extend(driver_config.get("callbacks", []))
    if points:
        entry_config = output.parent / f"{args.driver}_entries.conf"
        lines = []
        for point in points:
            function = str(point.get("function", "")).strip()
            label = str(point.get("label", "")).strip()
            if function and label:
                lines.append(f"{function} {label}")
        entry_config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = output.with_suffix(output.suffix + ".inputs.json")
    manifest.write_text(json.dumps({
        "linux": args.linux,
        "driver": args.driver,
        "input_set": args.input_set,
        "bitcode_root": str(root),
        "merged_bitcode": str(output),
        "inputs": [str(path) for path in inputs],
        "entry_config": str(entry_config) if entry_config else "",
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"merged_bitcode": str(output), "input_count": len(inputs), "manifest": str(manifest)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
