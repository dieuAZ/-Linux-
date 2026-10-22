#!/usr/bin/env python3
"""Syzkaller Workbench offline server. Python 3 standard library only."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from fuzz_metrics import read_metrics as read_fuzz_metrics, read_telemetry
from probe_completed_list import record_probe_completion

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
TASKS = DATA / "tasks"
DB_PATH = DATA / "tasks.db"
SYSTEM_CONFIG = ROOT / "config" / "system.json"
LLM_SETTINGS = DATA / "llm_settings.json"
PROBE_TARGETS = ROOT / "config" / "static_analysis_params.json"
FUZZ_TARGETS = ROOT / "config" / "B.json"
PROBE_COMPLETED_TARGETS = ROOT / "config" / "probe_completed.json"
SEED_TARGETS = ROOT / "config" / "C.json"
STATIC_PARAMS = ROOT / "config" / "static_analysis_params.json"
CODEQL_PACKAGE = ROOT / "codeql_query"
SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PROCESSES: dict[str, subprocess.Popen] = {}
LOCK = threading.RLock()
PIPELINES = None
_BITCODE_DIR_CACHE: dict[str, tuple[float, bool]] = {}


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def config() -> dict:
    return json.loads(SYSTEM_CONFIG.read_text(encoding="utf-8"))


def local_fuzz_mode() -> bool:
    return os.environ.get("WORKBENCH_FUZZ_MODE", "").strip().lower() in {"local", "standalone"}


def llm_settings(include_secret: bool = False) -> dict:
    defaults = config().get("backend", {}).get("probe_defaults", {})
    value = {
        "api_base": str(defaults.get("api_base", "https://api.deepseek.com")),
        "model": str(defaults.get("model", "deepseek-v4-pro")),
        "api_key": "",
    }
    if LLM_SETTINGS.exists():
        stored = json.loads(LLM_SETTINGS.read_text(encoding="utf-8"))
        if isinstance(stored, dict):
            value.update({key: str(stored.get(key, value[key])) for key in value})
    for field, env_name in (("api_base", "LLM_API_BASE"),
                            ("model", "LLM_MODEL"),
                            ("api_key", "LLM_API_KEY")):
        override = os.environ.get(env_name, "").strip()
        if override:
            value[field] = override
    result = {"api_base": value["api_base"], "model": value["model"], "has_api_key": bool(value["api_key"])}
    if include_secret:
        result["api_key"] = value["api_key"]
    return result


def save_llm_settings(payload: dict) -> dict:
    current = llm_settings(include_secret=True)
    api_base = str(payload.get("api_base", current["api_base"])).strip()
    model = str(payload.get("model", current["model"])).strip()
    api_key = str(payload.get("api_key", "")).strip() or current["api_key"]
    if not api_base:
        raise ValueError("请填写 LLM API 地址")
    if not model:
        raise ValueError("请填写 LLM 模型名称")
    if not api_key:
        raise ValueError("请填写 API Key")
    DATA.mkdir(exist_ok=True)
    LLM_SETTINGS.write_text(json.dumps({"api_base": api_base, "model": model, "api_key": api_key}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        LLM_SETTINGS.chmod(0o600)
    except OSError:
        pass
    sync_codeql_llm_settings()
    return {"api_base": api_base, "model": model, "has_api_key": True}


def sync_codeql_llm_settings() -> None:
    """Derive codeql_query/llm-settings.json from the system LLM configuration."""
    current = llm_settings(include_secret=True)
    api_base = str(current.get("api_base") or "").rstrip("/")
    if not api_base:
        return
    url = api_base if api_base.endswith("/chat/completions") else api_base + "/chat/completions"
    path = CODEQL_PACKAGE / "llm-settings.json"
    existing: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, json.JSONDecodeError):
            existing = {}
    screening = existing.get("ops_screening") if isinstance(existing.get("ops_screening"), dict) else {}
    settings = {
        "api": {
            "url": url,
            "model": str(current.get("model") or "deepseek-v4-pro"),
            "key": str(current.get("api_key") or ""),
            "key_env": "LLM_API_KEY",
            "timeout": 300,
            "max_tokens": 8192,
            "json_mode": True,
            "interval_seconds": 3,
        },
        "ops_screening": {
            "min_evidence_level": int(screening.get("min_evidence_level", 4)),
        },
    }
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    return conn


def init_storage() -> None:
    global PIPELINES
    DATA.mkdir(exist_ok=True)
    TASKS.mkdir(exist_ok=True)
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, slug TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL, linux_version TEXT NOT NULL,
                driver TEXT NOT NULL, number INTEGER NOT NULL,
                extra_enabled INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL, stage TEXT NOT NULL,
                manager_port INTEGER, pid INTEGER, exit_code INTEGER,
                created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                error_summary TEXT
            )
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
        if "task_type" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'FUZZ'")
        if "parent_task_id" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN parent_task_id TEXT")
        if "convergence_window_minutes" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN convergence_window_minutes INTEGER")
        if "max_duration_minutes" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN max_duration_minutes INTEGER")
    from pipeline import PipelineService
    PIPELINES = PipelineService(sys.modules[__name__])
    PIPELINES.initialize()


def read_catalog(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[str]] = {}
    items = raw if isinstance(raw, list) else [raw]
    for item in items:
        if not isinstance(item, dict):
            continue
        for linux, drivers in item.items():
            # The static-analysis parameter file stores the Linux-level
            # roots alongside a `drivers` array.  The public catalog still
            # exposes only driver names.
            if isinstance(drivers, dict):
                drivers = drivers.get("drivers", [])
            if isinstance(drivers, list):
                result.setdefault(str(linux), [])
                result[str(linux)].extend(
                    str(driver.get("name")) if isinstance(driver, dict) else str(driver)
                    for driver in drivers
                    if (not isinstance(driver, dict) or driver.get("name"))
                )
    return {linux: sorted(set(drivers)) for linux, drivers in result.items()}


def directory_has_bitcode(path: Path) -> bool:
    """Return whether a configured input directory contains any generated .bc file."""
    key = str(path.resolve())
    current = time.monotonic()
    cached = _BITCODE_DIR_CACHE.get(key)
    if cached and current - cached[0] < 5:
        return cached[1]
    found = False
    if path.is_dir():
        try:
            found = next(path.rglob("*.bc"), None) is not None
        except OSError:
            found = False
    _BITCODE_DIR_CACHE[key] = (current, found)
    return found


def driver_has_generated_bitcode(root: Path, driver: dict) -> bool:
    """A driver is eligible when at least one configured bitcode input exists."""
    for key in ("bitcode_files", "driver_fix_bitcode_files"):
        for rel in driver.get(key, []) or []:
            path = root / str(rel)
            if path.is_file() and path.suffix == ".bc":
                return True
    for key in ("bitcode_dirs", "driver_fix_bitcode_dirs"):
        for rel in driver.get(key, []) or []:
            if directory_has_bitcode(root / str(rel)):
                return True
    return False


def available_driver_catalog() -> dict[str, list[str]]:
    """Catalog of configured targets with at least one generated bitcode input."""
    raw = json.loads(PROBE_TARGETS.read_text(encoding="utf-8")) if PROBE_TARGETS.exists() else []
    catalog: dict[str, list[str]] = {}
    for entry in raw if isinstance(raw, list) else [raw]:
        if not isinstance(entry, dict):
            continue
        for linux, linux_config in entry.items():
            if not isinstance(linux_config, dict):
                continue
            root = Path(str(linux_config.get("bitcode_root", "")))
            names = [driver.get("name") for driver in linux_config.get("drivers", [])
                     if isinstance(driver, dict) and driver.get("name")
                     and driver_has_generated_bitcode(root, driver)]
            if names:
                catalog[str(linux)] = sorted(set(names))
    return catalog


def driver_catalog_with_reasons() -> tuple[dict[str, list[str]], dict[str, list[dict]]]:
    """Return runnable drivers and configured drivers excluded with clear reasons."""
    raw = json.loads(STATIC_PARAMS.read_text(encoding="utf-8")) if STATIC_PARAMS.exists() else []
    ready: dict[str, list[str]] = {}
    unavailable: dict[str, list[dict]] = {}
    entries = raw if isinstance(raw, list) else [raw]
    for item in entries:
        if not isinstance(item, dict):
            continue
        for linux, linux_config in item.items():
            if not isinstance(linux_config, dict):
                continue
            root_value = str(linux_config.get("bitcode_root", "")).strip()
            root = Path(root_value) if root_value else None
            ready.setdefault(str(linux), [])
            unavailable.setdefault(str(linux), [])
            for driver in linux_config.get("drivers", []):
                if not isinstance(driver, dict) or not driver.get("name"):
                    continue
                name = str(driver["name"])
                reasons = []
                if not root_value:
                    reasons.append("未配置该 Linux 版本的 bitcode_root")
                elif not root.is_dir():
                    reasons.append(f"bitcode 目录不存在：{root_value}")
                if root and driver_has_generated_bitcode(root, driver):
                    reasons = [reason for reason in reasons if not reason.startswith("bitcode 目录不存在：")]
                else:
                    declared = [str(path) for key in ("bitcode_files", "driver_fix_bitcode_files")
                                for path in (driver.get(key, []) or [])]
                    declared_dirs = [str(path) for key in ("bitcode_dirs", "driver_fix_bitcode_dirs")
                                     for path in (driver.get(key, []) or [])]
                    if driver.get("analysis_status") == "source_only" or not declared and not declared_dirs:
                        reasons.append("尚未生成 LLVM bitcode（当前只有源码记录）")
                    else:
                        missing = [path for path in declared if not root or not (root / path).is_file()]
                        if missing:
                            reasons.append("缺少 bitcode 文件：" + ", ".join(missing[:3]))
                        elif declared_dirs:
                            absent_dirs = [path for path in declared_dirs
                                           if not root or not directory_has_bitcode(root / path)]
                            if absent_dirs:
                                reasons.append("目录中没有 .bc 文件：" + ", ".join(absent_dirs[:3]))
                            else:
                                reasons.append("未找到可用的 LLVM bitcode")
                        else:
                            reasons.append("未找到可用的 LLVM bitcode")
                if reasons:
                    unavailable[str(linux)].append({"name": name, "reason": "；".join(dict.fromkeys(reasons))})
                else:
                    ready[str(linux)].append(name)
    for linux in ready:
        ready[linux] = sorted(set(ready[linux]))
        unavailable[linux].sort(key=lambda entry: entry["name"])
    return ready, unavailable


def codeql_kernel_root(linux: str) -> Path:
    """Resolve the physical Linux source tree used by CodeQL for a version label."""
    system = config().get("codeql_query", {})
    overrides = system.get("kernel_root_by_version", {})
    root = overrides.get(linux)
    if not root:
        raw = json.loads(STATIC_PARAMS.read_text(encoding="utf-8")) if STATIC_PARAMS.exists() else []
        for entry in raw if isinstance(raw, list) else [raw]:
            value = entry.get(linux) if isinstance(entry, dict) else None
            if isinstance(value, dict) and value.get("source_root"):
                root = value["source_root"]
                break
    root = root or system.get("kernel_root_template", "/media/iotteam/hd/pyh/mi/{linux_version}")
    return Path(str(root).format(linux_version=linux)).resolve()


def codeql_source_paths(root: Path) -> list[str]:
    """Return every selectable directory below a Linux source root."""
    if not root.is_dir():
        return []
    paths = ["."]
    for current, dirnames, _ in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
        current_path = Path(current)
        for name in dirnames:
            child = current_path / name
            if child.is_symlink():
                continue
            paths.append(child.relative_to(root).as_posix())
    return sorted(set(paths), key=lambda value: (value != ".", value.count("/"), value))


def codeql_catalog() -> dict[str, object]:
    """Return all real directories below each configured Linux source root."""
    system = config().get("codeql_query", {})
    versions = set(str(value) for value in system.get("kernel_root_by_version", {}).keys())
    raw = json.loads(STATIC_PARAMS.read_text(encoding="utf-8")) if STATIC_PARAMS.exists() else []
    for entry in raw if isinstance(raw, list) else [raw]:
        if isinstance(entry, dict):
            versions.update(str(value) for value in entry.keys())
    versions.add("linux-7.2.6")
    items: dict[str, list[str]] = {}
    roots: dict[str, str] = {}
    for linux in sorted(versions):
        root = codeql_kernel_root(linux)
        # The workbench only analyzes driver directories; hide the rest of the tree.
        paths = [p for p in codeql_source_paths(root)
                 if p == "drivers" or p.startswith("drivers/")]
        if paths:
            items[linux] = paths
            roots[linux] = str(root)
    return {"items": items, "roots": roots}


def validate_codeql_source_path(linux: str, relative: str) -> tuple[Path, str]:
    """Validate a user-selected Linux-relative directory and prevent path escape."""
    root = codeql_kernel_root(linux)
    if not root.is_dir():
        raise ValueError(f"Linux 源码根目录不存在：{root}")
    value = str(relative or ".").strip().replace("\\", "/")
    if value in {"", "."}:
        candidate, normalized = root, "."
    else:
        normalized = value.lstrip("/")
        candidate = (root / normalized).resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("源码路径必须位于 Linux 源码根目录内")
        if not candidate.is_dir():
            raise ValueError(f"Linux 源码目录不存在：{normalized}")
        normalized = candidate.relative_to(root).as_posix()
    return root, normalized


def device_metadata(linux: str, driver: str) -> dict:
    """Return the catalog metadata while keeping the public catalog name-only."""
    raw = json.loads(PROBE_TARGETS.read_text(encoding="utf-8")) if PROBE_TARGETS.exists() else []
    for item in raw if isinstance(raw, list) else [raw]:
        if not isinstance(item, dict) or linux not in item:
            continue
        value = item[linux]
        entries = value.get("drivers", []) if isinstance(value, dict) else value
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name") == driver:
                return dict(entry)
    return {}


def configured_linux_root(linux: str, fallback_template: str) -> Path:
    """Use the source root declared for a Linux version when available."""
    raw = json.loads(PROBE_TARGETS.read_text(encoding="utf-8")) if PROBE_TARGETS.exists() else []
    for item in raw if isinstance(raw, list) else [raw]:
        value = item.get(linux) if isinstance(item, dict) else None
        if isinstance(value, dict) and value.get("source_root"):
            return Path(str(value["source_root"])).resolve()
    return Path(fallback_template.format(linux_version=linux)).resolve()


def pipeline_targets(linux: str = "", query: str = "", limit: int = 50, offset: int = 0) -> dict:
    """Return searchable one-click pipeline targets with readiness details."""
    catalog, bitcode_unavailable = driver_catalog_with_reasons()
    raw = json.loads(STATIC_PARAMS.read_text(encoding="utf-8")) if STATIC_PARAMS.exists() else []
    metadata_by_version: dict[str, dict[str, dict]] = {}
    for entry in raw if isinstance(raw, list) else [raw]:
        if not isinstance(entry, dict):
            continue
        for version, linux_config in entry.items():
            if isinstance(linux_config, dict):
                metadata_by_version[str(version)] = {
                    str(driver.get("name")): dict(driver)
                    for driver in linux_config.get("drivers", [])
                    if isinstance(driver, dict) and driver.get("name")
                }
    with db() as conn:
        active_rows = conn.execute(
            "SELECT linux_version, driver FROM tasks "
            "WHERE status IN ('DRAFT','STARTING','RUNNING','READY_FOR_FUZZ','STOPPING')"
        ).fetchall()
    active = {(row[0], row[1]) for row in active_rows}
    if PIPELINES:
        active.update(PIPELINES.reserved_targets())
    configured_versions = sorted(metadata_by_version)
    versions = configured_versions
    selected_linux = linux if linux in versions else (versions[0] if versions else "")
    needle = query.strip().lower()
    candidates = [driver for driver in metadata_by_version.get(selected_linux, {})
                  if not needle or needle in driver.lower()]
    llm_ready = bool(llm_settings().get("has_api_key"))
    workflow_ready = PIPELINES is not None
    fuzz_config_ready = (ROOT / "config" / "test.config").is_file()
    bitcode_reasons = {entry["name"]: entry["reason"]
                       for entry in bitcode_unavailable.get(selected_linux, [])}
    items = []
    for driver in candidates[offset:offset + max(1, min(limit, 1000))]:
        metadata = metadata_by_version[selected_linux][driver]
        bitcode_ready = driver in catalog.get(selected_linux, [])
        device_ids = metadata.get("device_ids") or []
        probe_configured = bool(metadata.get("probe_entry_function") or metadata.get("probe_entry_functions"))
        checks = {
            "static_analysis": bitcode_ready,
            "probe": bool(device_ids) and probe_configured,
            "fuzz_config": fuzz_config_ready,
            "llm": llm_ready,
            "workflow": workflow_ready,
        }
        missing = []
        if not bitcode_ready:
            missing.append(bitcode_reasons.get(driver, "静态分析配置未生成可用的 LLVM bitcode"))
        if not checks["probe"]:
            absent = []
            if not device_ids:
                absent.append("未配置 VID/PID")
            if not probe_configured:
                absent.append("未配置 probe 入口函数")
            missing.append("驱动激活配置不完整：" + "、".join(absent))
        if not checks["fuzz_config"]:
            missing.append("缺少 Syzkaller 启动模板 config/test.config")
        if not checks["llm"]:
            missing.append("未配置 LLM API Key")
        if not checks["workflow"]:
            missing.append("Syzkaller 工作流未初始化")
        running = False
        ready = all(checks.values())
        if (selected_linux, driver) in active:
            ready = False
            running = True
            missing.append("该驱动已有任务正在运行")
        items.append({
            "linux_version": selected_linux,
            "driver": driver,
            "ready": ready and not running,
            "running": running,
            "checks": checks,
            "missing": missing,
        })
    items.sort(key=lambda item: (not item["ready"], item["driver"].lower()))
    return {"versions": versions, "linux_version": selected_linux, "items": items,
            "total": len(candidates), "ready_total": sum(item["ready"] for item in items),
            "unavailable_total": sum(not item["ready"] for item in items),
            "offset": offset, "limit": limit}


def static_target_metadata(linux: str, driver: str) -> tuple[dict, dict]:
    raw = json.loads(STATIC_PARAMS.read_text(encoding="utf-8")) if STATIC_PARAMS.exists() else []
    for item in raw if isinstance(raw, list) else [raw]:
        if not isinstance(item, dict) or linux not in item or not isinstance(item[linux], dict):
            continue
        linux_config = item[linux]
        for entry in linux_config.get("drivers", []):
            if isinstance(entry, dict) and entry.get("name") == driver:
                return dict(linux_config), dict(entry)
    raise ValueError(f"静态分析参数中没有目标：{linux}/{driver}")


def completed_probe_metadata(linux: str, driver: str) -> dict:
    """Build the structured entry written after a successful Probe."""
    linux_config, driver_config = static_target_metadata(linux, driver)
    metadata = device_metadata(linux, driver)
    defaults = config().get("backend", {}).get("probe_defaults", {})
    project_root = Path(str(defaults.get(
        "project_root", "/media/iotteam/hd/pyh/mi"))).resolve()
    linux_path = configured_linux_root(linux, str(defaults.get(
        "linux_path_template", str(project_root / "{linux_version}"))))
    # Tags are declared explicitly in static_analysis_params.json.  Do not
    # infer them from source path components: a path such as gpu/drm/tiny
    # describes code ownership, not necessarily a distinct userspace ABI.
    tags = set(driver_config.get("type_tags", []))
    value = {
        "linux_path": str(linux_path),
        "name": driver,
        "type_tags": sorted(tags),
        "vid": metadata.get("vid", ""),
        "pid": metadata.get("pid", ""),
    }
    for key in ("subvid", "subpid"):
        if metadata.get(key):
            value[key] = metadata[key]
    return value


def prepare_static_config(task: dict) -> None:
    system = config().get("static_analysis", {})
    linux_config, driver_config = static_target_metadata(task["linux_version"], task["driver"])
    source_template = str(system.get("linux_source_root_template", ""))
    source_root = configured_linux_root(task["linux_version"], source_template)
    output_root = Path(system.get("output_root", ""))
    output_dir = (output_root / task["linux_version"] / task["driver"]).resolve()
    # All persistent artifacts for one target share one directory.  The
    # bridges use temporary input staging only when a tool requires a folder.
    analysis_dir = output_dir
    merged_dir = output_dir
    collector_dir = output_dir
    collector_input_dir = output_dir / f"{task['driver']}.merged.llvm.bc"
    driver_fix_dir = output_dir
    driver_fix_input_dir = output_dir / f"{task['driver']}.driver_fix.llvm.bc"
    task_config = {
        "linux": task["linux_version"],
        "driver": task["driver"],
        "source_root": str(source_root),
        "bitcode_root": str(Path(linux_config["bitcode_root"]).resolve()),
        "vmlinux": str(source_root / "vmlinux"),
        "output_dir": str(output_dir),
        "merged_bitcode": str(merged_dir / f"{task['driver']}.merged.llvm.bc"),
        "driver_fix_bitcode": str(driver_fix_input_dir),
        "driver_fix_input_dir": str(driver_fix_input_dir),
        "collector_input_dir": str(collector_input_dir),
        "collector_output_dir": str(collector_dir),
        "collector_log": str(collector_dir / "collector.log"),
        "analysis_dir": str(analysis_dir),
        "analysis_log": str(output_dir / "backward_analyzer.log"),
        "index_dir": str(output_dir / "index"),
        "entry_config": str(output_dir / f"{task['driver']}_entries.conf"),
        "driver_fix_dir": str(driver_fix_dir),
        "probe_entry_function": driver_config.get("probe_entry_function", ""),
        "probe_entry_functions": driver_config.get("probe_entry_functions", []),
        "entry_points": driver_config.get("entry_points", []),
        "driver_config": driver_config,
        "tools": system.get("tools", {}),
        "environment": system.get("environment", {}),
    }
    target = task_dir(task) / "snapshot" / "configs" / "static_analysis.json"
    target.write_text(json.dumps(task_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare_codeql_config(task: dict, payload: dict) -> None:
    """Snapshot one CodeQL task for any Linux-relative in-tree directory."""
    system = config().get("codeql_query", {})
    kernel_root, relative = validate_codeql_source_path(task["linux_version"], task["driver"])
    selected = payload.get("queries", [
        "irq", "hrtimer", "kthread", "napi", "rcu", "tasklet", "timer", "workqueue", "ops"
    ])
    if not isinstance(selected, list) or not selected:
        raise ValueError("至少选择一种 CodeQL 查询")
    allowed = {"irq", "hrtimer", "kthread", "napi", "rcu", "tasklet", "timer", "workqueue", "ops"}
    queries = []
    for item in selected:
        name = str(item).strip().lower()
        if name not in allowed:
            raise ValueError(f"不支持的 CodeQL 查询：{item}")
        if name not in queries:
            queries.append(name)
    output_dir = task_dir(task) / "artifacts" / "codeql"
    database_root = Path(str(system.get(
        "database_root", "/media/iotteam/hd/lx/codeql-db"
    ))).resolve()
    task_config = {
        "task_id": task["id"],
        "codeql_path": str(system.get("codeql_path", "/media/iotteam/hd/lx/codeql/codeql")),
        "kernel_root": str(kernel_root),
        "driver_dir": str(kernel_root),
        "build_mode": "in_tree",
        "source_relative_path": relative,
        "query_root": str(CODEQL_PACKAGE.resolve()),
        "database_dir": str(database_root / f"{task['linux_version']}_{relative.replace('/', '__').replace('.', 'root')}"),
        "output_dir": str(output_dir.resolve()),
        "reuse_database": bool(payload.get("reuse_database", True)),
        "overwrite_database": False,
        "install_query_pack": bool(system.get("install_query_pack", False)),
        "threads": int(system.get("threads", 0)),
        "ram_mb": int(system.get("ram_mb", 16000)),
        "build_threads": int(system.get("build_threads", 16)),
        "arch": str(system.get("arch", "x86_64")),
        "prepare_commands": system.get("prepare_commands", []),
        "queries": queries,
        "llm_review": True,
        "llm_settings_file": str(LLM_SETTINGS.resolve()),
        "auto_retry_errors": bool(payload.get("auto_retry_errors", False)),
        "max_error_retries": 3,
    }
    target = task_dir(task) / "snapshot" / "configs" / "static_query.json"
    target.write_text(json.dumps(task_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare_fuzz_config(task: dict) -> None:
    """Create the Syzkaller config for a newly created Fuzz task."""
    settings = config()
    backend = settings.get("backend", {})
    defaults = backend.get("probe_defaults", {})
    project_root = Path(str(defaults.get("project_root", backend.get(
        "root", "/media/iotteam/hd/pyh/mi")))).resolve()
    linux_root = configured_linux_root(task["linux_version"], str(defaults.get(
        "linux_path_template", str(project_root / "{linux_version}"))))
    metadata = device_metadata(task["linux_version"], task["driver"])
    _, driver_config = static_target_metadata(task["linux_version"], task["driver"])

    syscall_config_path = ROOT / "config" / "syzkaller_syscall_sets.json"
    syscall_sets = json.loads(syscall_config_path.read_text(encoding="utf-8"))
    enabled: list[str] = []
    seen: set[str] = set()
    for syscall in syscall_sets.get("common", {}).get("syscalls", []):
        if syscall not in seen:
            enabled.append(str(syscall))
            seen.add(str(syscall))
    for tag in driver_config.get("type_tags", []):
        for syscall in syscall_sets.get("tag_sets", {}).get(str(tag), []):
            if syscall not in seen:
                enabled.append(str(syscall))
                seen.add(str(syscall))

    template_path = (ROOT / "config" / "test.config").resolve()
    if not template_path.is_file():
        raise ValueError(f"Fuzz 模板不存在：{template_path}")
    output_name = f"{task['linux_version']}_{task['driver']}"
    if local_fuzz_mode():
        container_linux_root = str(linux_root)
        container_qemu = str(project_root / "docker/fuzz6/runtime/qemu/qemu-system-x86_64")
    else:
        container_linux_root = f"/opt/fuzz6/runtime/{task['linux_version']}"
        container_qemu = "/opt/fuzz6/runtime/qemu/qemu-system-x86_64"
    target = (task_dir(task) / "snapshot" / "configs" / "fuzz.config").resolve()
    shutil.copy2(template_path, target)
    template = json.loads(target.read_text(encoding="utf-8"))
    output_dir = str(project_root / "out" / "workbench" / task['slug'])
    vid = str(metadata.get("vid", "")).removeprefix("0x")
    pid = str(metadata.get("pid", "")).removeprefix("0x")

    replacements = {
        "{{LINUX_ROOT}}": str(linux_root),
        "{{CONTAINER_LINUX_ROOT}}": container_linux_root,
        "{{CONTAINER_QEMU}}": container_qemu,
        "{{FUZZ_WORKDIR}}": output_dir,
        "{{MANAGER_PORT}}": str(task["manager_port"]),
        "{{DRIVER}}": task["driver"],
        "{{VID}}": vid,
        "{{PID}}": pid,
        "{{ENABLE_SYSCALLS}}": enabled,
    }

    def replace(value):
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, str):
            if value in replacements:
                return replacements[value]
            for source, replacement in replacements.items():
                if not isinstance(replacement, str):
                    continue
                value = value.replace(source, replacement)
        return value

    template = replace(template)
    template.update({
        "kernel_obj": container_linux_root,
        "kernel_src": container_linux_root,
        "module_obj": [container_linux_root + "/drivers"],
        "workdir": output_dir,
        "http": f":{task['manager_port']}",
        "enable_syscalls": enabled,
    })
    env = template.setdefault("env", {})
    env.update({
        "SFP_DEV_MODEL": task["driver"],
        "SFP_VID": vid,
        "SFP_PID": pid,
    })
    vm = template.setdefault("vm", {})
    vm["qemu"] = container_qemu
    vm["kernel"] = container_linux_root + "/arch/x86/boot/bzImage"
    target.write_text(json.dumps(template, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare_seed_config(task: dict) -> None:
    """Create the persistent seed_gener config for a Fuzz task's corpus."""
    settings = config()
    backend = settings.get("backend", {})
    defaults = backend.get("probe_defaults", {})
    project_root = Path(str(defaults.get("project_root", backend.get(
        "root", "/media/iotteam/hd/pyh/mi")))).resolve()
    linux_root = configured_linux_root(task["linux_version"], str(defaults.get(
        "linux_path_template", str(project_root / "{linux_version}"))))
    output_root = Path(str(settings.get("static_analysis", {}).get(
        "output_root", project_root / "ana/StateFuzz/sv-collector/result"))).resolve()
    static_root = output_root / task["linux_version"] / task["driver"]
    analysis_root = static_root
    corpus_root = task_dir(task) / "artifacts" / "seed"
    corpus_root.mkdir(parents=True, exist_ok=True)
    metadata = device_metadata(task["linux_version"], task["driver"])
    _, driver_config = static_target_metadata(task["linux_version"], task["driver"])
    llm = llm_settings()

    task_configs_dir = task_dir(task) / "snapshot" / "configs"
    task_configs_dir.mkdir(parents=True, exist_ok=True)
    host_config_path = task_configs_dir / "syzkaller.config"
    host_template_path = (ROOT / "config" / "test.config").resolve()
    if not host_template_path.is_file():
        raise ValueError(f"Seed 的 Syzkaller 模板不存在：{host_template_path}")
    host_template = json.loads(host_template_path.read_text(encoding="utf-8"))
    host_template.update({
        "http": f":{task['manager_port']}",
        "workdir": str(corpus_root),
        "kernel_obj": str(linux_root),
        "kernel_src": str(linux_root),
        "module_obj": [str(linux_root / "drivers")],
        "image": str(project_root / "image" / "bullseye.img"),
        "sshkey": str(project_root / "image" / "bullseye.id_rsa"),
        "syzkaller": str(project_root / "syzkaller"),
        "enable_syscalls": syscall_list_for_driver(driver_config),
        "disable_syscalls": [],
    })
    env = host_template.setdefault("env", {})
    env.update({
        "SFP_DEV_MODEL": task["driver"],
        "SFP_VID": str(metadata.get("vid", "")).removeprefix("0x"),
        "SFP_PID": str(metadata.get("pid", "")).removeprefix("0x"),
    })
    vm = host_template.setdefault("vm", {})
    vm["qemu"] = str(
        project_root / "docker/fuzz6/runtime/qemu/qemu-system-x86_64"
        if local_fuzz_mode()
        else project_root / "build-qemu-exp" / "x86_64-softmmu" / "qemu-system-x86_64"
    )
    vm["kernel"] = str(linux_root / "arch/x86/boot/bzImage")
    host_config_path.write_text(json.dumps(host_template, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Keep a private copy of the seed generator template in the workbench.
    # The source file under the analysis project is treated as an upstream
    # reference and is never modified by task creation.
    seed_template_path = (ROOT / "config" / "seed_gener.config.json").resolve()
    if not seed_template_path.is_file():
        raise ValueError(f"Seed 生成模板不存在：{seed_template_path}")
    seed_config = json.loads(seed_template_path.read_text(encoding="utf-8"))

    # The checked-in template is reusable across drivers.  Expand its public
    # task placeholders before applying the authoritative paths below.
    replacements = {
        "{{DRIVER}}": task["driver"],
        "{{LINUX_VERSION}}": task["linux_version"],
        "{{MANAGER_PORT}}": str(task["manager_port"]),
        "{{BASE_URL}}": f"http://127.0.0.1:{task['manager_port']}",
        "{{CORPUS_ROOT}}": str(corpus_root),
        "{{STATIC_ANALYSIS_ROOT}}": str(static_root),
        "{{LINUX_ROOT}}": str(linux_root),
        "{{API_BASE}}": str(llm.get("api_base", "")),
        "{{MODEL}}": str(llm.get("model", "")),
        "{{SYZKALLER_CONFIG}}": str(host_config_path),
        "{{ADDR2LINE_PATH}}": str(linux_root / "drivers" / (driver_config.get("source_rel", [""])[0] if driver_config.get("source_rel") else "")),
        "{{ENTRY_CONFIG}}": str(analysis_root / f"{task['driver']}_entries.conf"),
        "{{INDEX_DIR}}": str(analysis_root / "index"),
    }
    def expand(value):
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, str):
            for old, new in replacements.items():
                value = value.replace(old, new)
        return value
    seed_config = expand(seed_config)

    source_rel = driver_config.get("source_rel", [])
    source_rel = source_rel[0] if source_rel else ""
    seed_config.update({
        "driver_name": task["driver"],
        "base_url": f"http://127.0.0.1:{task['manager_port']}",
        "out_dir": str(corpus_root),
        "static_analysis_dir": str(static_root),
        "linux": str(linux_root),
        "api_base": str(llm.get("api_base", "")),
        "model": str(llm.get("model", "")),
        "syzkaller-config": str(host_config_path),
        "addr2line_inline_path_prefix": str(linux_root / "drivers" / source_rel),
    })
    backward_query = seed_config.setdefault("backward_query", {})
    backward_query.update({
        "entry_config": str(analysis_root / f"{task['driver']}_entries.conf"),
        "index_dir": str(analysis_root / "index"),
    })
    target = task_configs_dir / "seed.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(seed_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def syscall_list_for_driver(driver_config: dict) -> list[str]:
    syscall_sets = json.loads((ROOT / "config" / "syzkaller_syscall_sets.json").read_text(encoding="utf-8"))
    result, seen = [], set()
    values = list(syscall_sets.get("common", {}).get("syscalls", []))
    for tag in driver_config.get("type_tags", []):
        values.extend(syscall_sets.get("tag_sets", {}).get(str(tag), []))
    for value in values:
        value = str(value)
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def write_catalog(path: Path, catalog: dict[str, list[str]]) -> None:
    normalized = [{linux: sorted(set(drivers))} for linux, drivers in sorted(catalog.items())]
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def add_target(path: Path, linux: str, driver: str) -> None:
    with LOCK:
        catalog = read_catalog(path)
        catalog.setdefault(linux, [])
        if driver not in catalog[linux]:
            catalog[linux].append(driver)
            write_catalog(path, catalog)


def fuzz_catalog() -> dict[str, list[str]]:
    # Probe completion is the authoritative Fuzz target list. B.json is only
    # a legacy compatibility catalog and can lag behind probe_completed.json.
    probe_ready = read_catalog(PROBE_COMPLETED_TARGETS)
    return probe_ready


def row_dict(row: sqlite3.Row | None) -> dict | None:
    if not row:
        return None
    value = dict(row)
    value["extra_enabled"] = bool(value["extra_enabled"])
    value["manager_url"] = f"http://127.0.0.1:{value['manager_port']}" if value["manager_port"] else None
    value["ready_for_fuzz"] = value["status"] == "READY_FOR_FUZZ"
    return value


def get_task(task_id: str) -> dict | None:
    with db() as conn:
        task = row_dict(conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone())
    if task:
        report_path = task_dir(task) / "snapshot" / "report.json"
        task["report"] = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
        if task["task_type"] == "FUZZ":
            metrics = read_fuzz_metrics(task_dir(task))
            if metrics:
                report = task["report"] or {}
                task["report"] = {**report, "metrics": {**report.get("metrics", {}), **metrics}}
        elif task["task_type"] == "CODEQL_QUERY":
            status_path = task_dir(task) / "artifacts" / "codeql" / "status.json"
            if status_path.is_file():
                status = json.loads(status_path.read_text(encoding="utf-8"))
                task["report"] = {**(task["report"] or {}), "codeql_query": status}
    return task


def list_tasks() -> list[dict]:
    with db() as conn:
        return [row_dict(row) for row in conn.execute("SELECT * FROM tasks ORDER BY created_at DESC")]


def task_dir(task: dict) -> Path:
    path = (TASKS / task["slug"]).resolve()
    if TASKS.resolve() not in path.parents:
        raise ValueError("invalid task path")
    return path


def append_event(task: dict, event: str, payload: dict) -> None:
    target = task_dir(task) / "events.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps({"time": now(), "event": event, **payload}, ensure_ascii=False) + "\n")


def prepare_probe_config(task: dict, payload: dict) -> None:
    """Generate complete static/deep Probe inputs for one task.

    The Probe backend reads OPENAI_API_KEY from its environment, so the secret
    is kept outside both generated JSON files.
    """
    backend = config().get("backend", {})
    defaults = backend.get("probe_defaults", {})
    saved_llm = llm_settings(include_secret=True)
    api_base = str(payload.get("api_base") or saved_llm["api_base"]).strip()
    model = str(payload.get("model") or saved_llm["model"]).strip()
    api_key = str(payload.get("api_key") or saved_llm["api_key"]).strip()
    if not api_base:
        raise ValueError("请填写 LLM API 地址")
    if not model:
        raise ValueError("请填写 LLM 模型名称")
    if task.get("task_type") == "PROBE" and not api_key:
        raise ValueError("尚未配置 LLM，请先到系统配置页面填写 API 地址、模型名称和 API Key")

    project_root = Path(str(defaults.get("project_root", backend.get("root", "/media/iotteam/hd/pyh/mi")))).resolve()
    linux_root = configured_linux_root(task["linux_version"], str(defaults.get(
        "linux_path_template", str(project_root / "{linux_version}"))))
    output_root = Path(str(config().get("static_analysis", {}).get(
        "output_root", project_root / "ana/StateFuzz/sv-collector/result"))).resolve()
    driver = task["driver"]
    analysis_output = output_root / task["linux_version"] / driver
    model_root = (project_root / "afl-proxy" / "aplib").resolve()
    metadata = device_metadata(task["linux_version"], driver)
    common = {
        "driver": driver,
        "SFP_VID": metadata.get("vid", ""), "SFP_PID": metadata.get("pid", ""),
        "SFP_SUBVID": metadata.get("subvid", ""), "SFP_SUBPID": metadata.get("subpid", ""),
        "linux_path": str(linux_root), "project_root": str(project_root),
        "output_dir": str(analysis_output.resolve()),
        "model_root": str(model_root),
        "afl_proxy_root": str((project_root / "afl-proxy").resolve()),
        "qemu_source_root": str((project_root / "qemu").resolve()),
        "qemu_build_root": str((project_root / "build-qemu-exp").resolve()),
        **({"qemu_binary": str(project_root / "docker/fuzz6/runtime/qemu/qemu-system-x86_64")}
           if local_fuzz_mode() else {}),
        "image_path": str((project_root / "image" / "bullseye.img").resolve()),
        "guest_ssh_key": str(defaults.get(
            "guest_ssh_key", project_root / "image" / "bullseye.id_rsa")),
        "api_base": api_base, "model": model,
        "message": str((analysis_output / f"{driver}_dmesg.txt").resolve()),
        "message_list": str((analysis_output / f"{driver}_dmesg_list.json").resolve()),
        "read_fun": str((analysis_output / "read_fund.txt").resolve()),
        "read_list": str((analysis_output / "read_list.txt").resolve()),
        "model_file": str((model_root / "pci" / f"HWModel_{driver}.h").resolve()),
        "dma_model_root": str(model_root), "max_rounds": 30,
    }
    configs_dir = task_dir(task) / "snapshot" / "configs"
    for mode in ("static", "deep"):
        (configs_dir / f"probe_{mode}.json").write_text(
            json.dumps({"mode": mode, **common}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
    if api_key:
        secret = configs_dir / "probe_credentials.json"
        secret.write_text(json.dumps({"OPENAI_API_KEY": api_key}, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            secret.chmod(0o600)
        except OSError:
            pass
    (task_dir(task) / "snapshot" / "probe_source.json").write_text(
        json.dumps({"generated": True, "modes": ["static", "deep"],
                    "api_key": "environment-only"},
                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def command_available(command: list[str]) -> bool:
    if not command:
        return False
    executable = Path(command[0])
    return executable.exists() if executable.is_absolute() else bool(shutil_which(command[0]))


def shutil_which(name: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(folder) / name
        if candidate.exists():
            return str(candidate)
    return None


def allocate_port() -> int:
    cfg = config()["manager_port_range"]
    with LOCK, db() as conn:
        used = {row[0] for row in conn.execute(
            "SELECT manager_port FROM tasks WHERE manager_port IS NOT NULL AND status IN ('DRAFT','STARTING','RUNNING','READY_FOR_FUZZ','STOPPING')"
        )}
        for port in range(cfg["start"], cfg["end"] + 1):
            if port in used:
                continue
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port
    raise RuntimeError("端口范围内没有空闲端口")


def create_task(payload: dict, pipeline_id: str | None = None) -> dict:
    with LOCK:
        if PIPELINES:
            PIPELINES.check_task_creation(payload, pipeline_id)
        return _create_task(payload)


def _create_task(payload: dict) -> dict:
    task_type = str(payload.get("task_type", "")).strip().upper()
    if task_type not in {"STATIC_ANALYSIS", "PROBE", "FUZZ", "SEED", "CODEQL_QUERY"}:
        raise ValueError("不支持的任务类型")
    parent_task_id = payload.get("parent_task_id")
    parent = get_task(str(parent_task_id)) if parent_task_id else None
    if task_type == "SEED":
        if not parent or parent["task_type"] != "FUZZ":
            raise ValueError("Seed 必须由一个 Fuzz 任务创建")
        if parent["status"] not in {"STARTING", "RUNNING", "READY_FOR_FUZZ"}:
            raise ValueError("只能对当前正在执行的 Fuzz 提前生成种子")
        linux, driver = parent["linux_version"], parent["driver"]
    else:
        linux = str(payload.get("linux_version", "")).strip()
        driver = str(payload.get("driver", "")).strip()
    catalog = ({
        "STATIC_ANALYSIS": available_driver_catalog(),
        "PROBE": available_driver_catalog(),
        "FUZZ": fuzz_catalog(),
        "SEED": read_catalog(SEED_TARGETS),
        "CODEQL_QUERY": {},
    })[task_type]
    if task_type == "CODEQL_QUERY":
        _, driver = validate_codeql_source_path(linux, driver)
    elif task_type != "SEED" and (linux not in catalog or driver not in catalog[linux]):
        raise ValueError(f"{task_type} 目标不在对应清单中")
    with db() as conn:
        number = int(conn.execute("SELECT COALESCE(MAX(number), 0) + 1 FROM tasks").fetchone()[0])
    convergence_window = int(payload.get("convergence_window_minutes", 30)) if task_type == "FUZZ" else None
    max_duration = int(payload.get("max_duration_minutes", 180)) if task_type == "FUZZ" else None
    if task_type == "FUZZ" and not (1 <= convergence_window <= 1440):
        raise ValueError("收敛窗口必须在 1–1440 分钟之间")
    if task_type == "FUZZ" and not (1 <= max_duration <= 10080):
        raise ValueError("每轮最长时间必须在 1–10080 分钟之间")
    slug_driver = driver.replace("/", "__") if task_type == "CODEQL_QUERY" else driver
    slug = f"{task_type.lower()}_{linux}_{slug_driver}_{number:03d}"
    if not SLUG_RE.fullmatch(slug) or ".." in slug:
        raise ValueError("版本或驱动名称包含不安全字符")
    task_id = str(uuid.uuid4())
    reserved_port = allocate_port() if task_type == "FUZZ" else None
    task = {
        "id": task_id, "slug": slug, "display_name": f"{task_type} · {linux} / {driver}",
        "linux_version": linux, "driver": driver, "number": number,
        "task_type": task_type,
        "parent_task_id": parent["id"] if parent else None,
        "manager_port": parent["manager_port"] if parent else reserved_port,
        "convergence_window_minutes": convergence_window,
        "max_duration_minutes": max_duration,
        "extra_enabled": bool(payload.get("extra_enabled", False)),
        "status": "DRAFT", "stage": "NOT_STARTED", "created_at": now()
    }
    with db() as conn:
        conn.execute("""INSERT INTO tasks
            (id,slug,display_name,linux_version,driver,number,extra_enabled,status,stage,created_at,task_type,parent_task_id,manager_port,convergence_window_minutes,max_duration_minutes)
            VALUES (:id,:slug,:display_name,:linux_version,:driver,:number,:extra_enabled,:status,:stage,:created_at,:task_type,:parent_task_id,:manager_port,:convergence_window_minutes,:max_duration_minutes)""", task)
    folder = TASKS / slug
    (folder / "snapshot" / "configs").mkdir(parents=True)
    (folder / "logs").mkdir()
    (folder / "artifacts").mkdir()
    (folder / "snapshot" / "task.json").write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        if task_type == "STATIC_ANALYSIS":
            prepare_static_config(task)
        if task_type == "FUZZ":
            prepare_fuzz_config(task)
        if task_type == "SEED":
            prepare_seed_config(task)
        if task_type == "PROBE":
            prepare_probe_config(task, payload)
        if task_type == "CODEQL_QUERY":
            prepare_codeql_config(task, payload)
    except Exception as exc:
        with db() as conn:
            conn.execute("UPDATE tasks SET status='FAILED', stage='CONFIG_FAILED', error_summary=? WHERE id=?", (str(exc), task_id))
        raise
    append_event(task, "task_created", {"status": "DRAFT"})
    return get_task(task_id)


def build_command(task: dict) -> tuple[list[str], Path]:
    cfg = config()
    runner = cfg.get("workflow_runner", {})
    argv = runner.get("argv", [])
    if task["task_type"] == "STATIC_ANALYSIS":
        return ["python3", str(ROOT / "static_analysis_bridge.py"),
                "--task-id", task["id"], "--task-dir", str(task_dir(task))], ROOT
    if task["task_type"] == "PROBE":
        argv = ["python3", str(ROOT / "backend_bridge.py"),
                "--task-id", task["id"], "--task-dir", str(task_dir(task)),
                "--driver", task["driver"]]
        return argv, ROOT
    if task["task_type"] == "CODEQL_QUERY":
        return ["python3", str(ROOT / "codeql_query_bridge.py"),
                "--task-id", task["id"], "--task-dir", str(task_dir(task))], ROOT
    if task["task_type"] == "FUZZ":
        config_path = (task_dir(task) / "snapshot" / "configs" / "fuzz.config").resolve()
        if not config_path.is_file():
            raise RuntimeError(f"缺少 Fuzz 配置：{config_path}")
        if local_fuzz_mode():
            project_root = Path(str(cfg.get("backend", {}).get("root", "/media/iotteam/hd/pyh/mi")))
            manager = project_root / "syzkaller/bin/syz-manager"
            if not manager.is_file():
                raise RuntimeError(f"Syzkaller 不存在：{manager}")
            return [str(manager), f"-config={config_path}"], ROOT
        container_config = f"/tmp/{task['linux_version']}_{task['driver']}.config"
        container_name = fuzz_container_name(task)
        project_root = str(cfg.get("backend", {}).get("root", "/media/iotteam/hd/pyh/mi"))
        runtime = f"{project_root}/docker/fuzz6/runtime"
        argv = [
            "docker", "run", "--rm", "--name", container_name,
            "--device", "/dev/kvm:/dev/kvm", "--privileged",
            "--shm-size", "1g", "--network", "host",
            "-v", f"{project_root}:{project_root}",
            "-v", f"{runtime}/{task['linux_version']}:/opt/fuzz6/runtime/{task['linux_version']}:ro",
            "-v", f"{runtime}/qemu:/opt/fuzz6/runtime/qemu:ro",
            "-v", f"{runtime}/afl-proxy:{project_root}/afl-proxy:ro",
            "-v", f"{config_path}:{container_config}:ro",
            "mi-syzkaller-fuzz6:latest", container_config,
        ]
        return argv, ROOT
    if task["task_type"] == "SEED":
        seed_config = (task_dir(task) / "snapshot" / "configs" / "seed.json").resolve()
        if not seed_config.is_file():
            raise RuntimeError(f"缺少 Seed 配置：{seed_config}")
        return [sys.executable,
                "/media/iotteam/hd/pyh/mi/scripts/seed_gener/main.py",
                str(seed_config)], ROOT
    if not argv:
        raise RuntimeError("尚未在 config/system.json 配置 workflow_runner.argv")
    replacements = {
        "{task_id}": task["id"], "{slug}": task["slug"],
        "{task_dir}": str(task_dir(task)), "{linux_version}": task["linux_version"],
        "{driver}": task["driver"], "{task_type}": task["task_type"],
        "{parent_task_id}": str(task.get("parent_task_id") or ""),
        "{convergence_window_minutes}": str(task.get("convergence_window_minutes") or ""),
        "{max_duration_minutes}": str(task.get("max_duration_minutes") or ""),
        "{manager_port}": str(task["manager_port"] or ""),
    }
    resolved = []
    for part in argv:
        text = str(part)
        for key, value in replacements.items():
            text = text.replace(key, value)
        resolved.append(text)
    if not command_available(resolved):
        raise RuntimeError(f"工作流程序不存在：{resolved[0]}")
    workdir = Path(runner.get("cwd", str(ROOT)))
    return resolved, workdir


def fuzz_container_name(task: dict) -> str:
    return f"syzkaller-fuzz-{task['slug']}"


def monitor(task_id: str, process: subprocess.Popen, log_fp) -> None:
    code = process.wait()
    log_fp.close()
    with LOCK, db() as conn:
        current = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
        status = "CANCELLED" if current and current[0] == "STOPPING" else ("COMPLETED" if code == 0 and (not current or current[0] != 'FAILED') else "FAILED")
        conn.execute("UPDATE tasks SET status=?, stage=?, exit_code=?, finished_at=? WHERE id=?",
                     (status, "FINISHED", code, now(), task_id))
        PROCESSES.pop(task_id, None)
    task = get_task(task_id)
    if task and task["task_type"] == "SEED" and code == 0:
        add_target(SEED_TARGETS, task["linux_version"], task["driver"])
        append_event(task, "seed_target_completed", {
            "linux_version": task["linux_version"],
            "driver": task["driver"],
        })
    append_event(task, "process_exited", {"status": status, "exit_code": code})


def start_task(task_id: str, pipeline_id: str | None = None) -> dict:
    with LOCK:
        task = get_task(task_id)
        if not task:
            raise KeyError("任务不存在")
        if PIPELINES:
            PIPELINES.check_task_creation(task, pipeline_id)
        if task["status"] not in {"DRAFT", "FAILED", "CANCELLED"}:
            raise RuntimeError("当前任务状态不能启动")
        port = (task["manager_port"] or allocate_port()) if task["task_type"] == "FUZZ" else None
        with db() as conn:
            if task["task_type"] == "FUZZ":
                conn.execute("UPDATE tasks SET manager_port=?, status='STARTING', stage='PREPARING', error_summary=NULL WHERE id=?", (port, task_id))
            else:
                conn.execute("UPDATE tasks SET status='STARTING', stage='PREPARING', error_summary=NULL WHERE id=?", (task_id,))
        task = get_task(task_id)
        try:
            if task['task_type'] == 'FUZZ' and not (task_dir(task) / 'snapshot' / 'configs' / 'fuzz.config').is_file():
                prepare_fuzz_config(task)
            argv, workdir = build_command(task)
            snapshot = task_dir(task) / "snapshot"
            (snapshot / "commands.json").write_text(json.dumps({"argv": argv, "cwd": str(workdir)}, ensure_ascii=False, indent=2), encoding="utf-8")
            log_name = "seed.log" if task["task_type"] == "SEED" else "workflow.log"
            log_path = task_dir(task) / "logs" / log_name
            log_fp = log_path.open("ab", buffering=0)
            kwargs = {"cwd": workdir, "stdout": log_fp, "stderr": subprocess.STDOUT}
            if task["task_type"] == "PROBE":
                credentials = task_dir(task) / "snapshot" / "configs" / "probe_credentials.json"
                if credentials.is_file():
                    secret = json.loads(credentials.read_text(encoding="utf-8"))
                    child_env = os.environ.copy()
                    api_key = str(secret.get("OPENAI_API_KEY", "")).strip()
                    if api_key:
                        child_env["OPENAI_API_KEY"] = api_key
                    kwargs["env"] = child_env
            if os.name != "nt":
                kwargs["start_new_session"] = True
            process = subprocess.Popen(argv, **kwargs)
            PROCESSES[task_id] = process
            with db() as conn:
                conn.execute("UPDATE tasks SET status='RUNNING', stage='WORKFLOW', pid=?, started_at=? WHERE id=?", (process.pid, now(), task_id))
            append_event(get_task(task_id), "process_started", {"pid": process.pid, "manager_port": port})
            threading.Thread(target=monitor, args=(task_id, process, log_fp), daemon=True).start()
        except Exception as exc:
            with db() as conn:
                conn.execute("UPDATE tasks SET status='FAILED', stage='START_FAILED', error_summary=?, finished_at=? WHERE id=?", (str(exc), now(), task_id))
            append_event(get_task(task_id), "start_failed", {"error": str(exc)})
            raise
    return get_task(task_id)


def stop_task(task_id: str) -> dict:
    with LOCK:
        task = get_task(task_id)
        if not task:
            raise KeyError("任务不存在")
        if task["status"] not in {"STARTING", "RUNNING", "STOPPING", "READY_FOR_FUZZ"}:
            raise RuntimeError("当前任务没有运行")

        process = PROCESSES.get(task_id)
        managed = process is not None and process.poll() is None
        if process is not None and not managed:
            raise RuntimeError("任务进程已退出，等待状态更新")

        container_running = False
        recovered_pid = None
        if task["task_type"] == "FUZZ" and not local_fuzz_mode():
            inspected = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", fuzz_container_name(task)],
                capture_output=True, text=True, timeout=10,
            )
            container_running = inspected.returncode == 0 and inspected.stdout.strip() == "true"
        elif not managed:
            if os.name == "nt":
                raise RuntimeError("服务重启后无法在 Windows 上安全恢复任务进程")
            recovered_pid = int(task.get("pid") or 0)
            command_path = task_dir(task) / "snapshot" / "commands.json"
            expected = json.loads(command_path.read_text(encoding="utf-8")).get("argv", [])
            if not recovered_pid or not expected:
                raise RuntimeError("缺少任务进程或命令快照，无法安全停止")
            proc_cmdline = Path(f"/proc/{recovered_pid}/cmdline")
            if proc_cmdline.exists():
                actual = [os.fsdecode(arg) for arg in proc_cmdline.read_bytes().split(b"\0") if arg]
                if (not actual or os.path.basename(actual[0]) != os.path.basename(str(expected[0]))
                        or actual[1:] != [str(arg) for arg in expected[1:]]
                        or os.getsid(recovered_pid) != recovered_pid):
                    raise RuntimeError("任务 PID 已被其他进程占用，拒绝停止")
            else:
                recovered_pid = None

        if not managed and not container_running and recovered_pid is None:
            with db() as conn:
                conn.execute(
                    "UPDATE tasks SET status='FAILED', stage='FINISHED', error_summary=?, finished_at=? WHERE id=?",
                    ("任务进程已不存在（可能是服务重启后进程退出）", now(), task_id),
                )
            append_event(get_task(task_id), "process_missing", {})
            return get_task(task_id)

        with db() as conn:
            conn.execute("UPDATE tasks SET status='STOPPING' WHERE id=?", (task_id,))
        try:
            if task["task_type"] == "FUZZ" and container_running:
                subprocess.run(
                    ["docker", "stop", "-t", "10", fuzz_container_name(task)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=True, timeout=25,
                )
            elif managed and os.name == "nt":
                process.terminate()
            else:
                os.killpg(process.pid if managed else recovered_pid, signal.SIGTERM)
        except Exception:
            with db() as conn:
                conn.execute("UPDATE tasks SET status=? WHERE id=?", (task["status"], task_id))
            raise

        append_event(get_task(task_id), "stop_requested", {"recovered": not managed})
        if not managed:
            with db() as conn:
                conn.execute(
                    "UPDATE tasks SET status='CANCELLED', stage='FINISHED', finished_at=? WHERE id=?",
                    (now(), task_id),
                )
        return get_task(task_id)

def delete_task(task_id: str) -> dict:
    """Permanently remove a task record and its task-local artifacts."""
    with LOCK:
        task = get_task(task_id)
        if not task:
            raise KeyError("任务不存在")
        if PIPELINES and any(task_id in p['tasks'] and p['status'] in {'QUEUED','RUNNING','STOPPING','INTERRUPTED'} for p in PIPELINES.list()):
            raise RuntimeError('任务属于未结束的流水线，请先停止流水线')
        if task["status"] in {"STARTING", "RUNNING", "READY_FOR_FUZZ", "STOPPING"}:
            raise RuntimeError("运行中的任务不能删除，请先停止任务")
        process = PROCESSES.get(task_id)
        if process and process.poll() is None:
            raise RuntimeError("任务进程仍在运行，请先停止任务")
        target = task_dir(task)
        if target.exists():
            shutil.rmtree(target)
        with db() as conn:
            deleted = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,)).rowcount
        if not deleted:
            raise KeyError("任务不存在")
        PROCESSES.pop(task_id, None)
    return {"ok": True, "id": task_id}


def merge_dict(base: dict, patch: dict) -> dict:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge_dict(base[key], value)
        else:
            base[key] = value
    return base


def start_codeql_error_retry(task: dict) -> dict:
    """Re-run LLM triage for the errored units of a finished CodeQL task."""
    if task.get("task_type") != "CODEQL_QUERY":
        raise ValueError("仅 CodeQL 查询任务支持重试")
    base = task_dir(task) / "artifacts" / "codeql"
    input_csv = base / "semantic_dedup" / "all_models_semantic.csv"
    if not input_csv.is_file():
        raise RuntimeError("尚未生成语义合并结果，无法重试")
    settings_path = CODEQL_PACKAGE / "llm-settings.json"
    if not settings_path.is_file():
        raise RuntimeError("LLM 配置不存在")
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    api = settings.get("api") if isinstance(settings.get("api"), dict) else {}
    endpoint = str(api.get("url") or settings.get("api_base") or "")
    model = str(api.get("model") or settings.get("model") or "")
    key_env = str(api.get("key_env") or "LLM_API_KEY")
    api_key = str(api.get("key") or settings.get("api_key") or os.environ.get(key_env, ""))
    if not endpoint or not model or not api_key:
        raise RuntimeError("LLM 配置缺少 endpoint/model/key")
    env = os.environ.copy()
    env[key_env] = api_key
    cmd = [sys.executable, str(CODEQL_PACKAGE / "llm-triage" / "llm_vulnerability_triage.py"),
           "--input-csv", str(input_csv),
           "--source-root", str(codeql_kernel_root(task["linux_version"])),
           "--output-dir", str(base),
           "--prompt-dir", str(CODEQL_PACKAGE / "llm-triage" / "prompts"),
           "--endpoint", endpoint, "--model", model,
           "--api-key-env", key_env, "--timeout", "300", "--max-output-tokens", "8192",
           "--interval-seconds", "3", "--retry-errors"]
    status_path = base / "status.json"
    log_path = task_dir(task) / "logs" / "workflow.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def update_status(progress_value: str, message: str, counts: dict | None = None) -> None:
        if not status_path.is_file():
            return
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        status.setdefault("progress", {})["llm_review"] = progress_value
        status["message"] = message
        status["updated_at"] = now()
        if counts is not None:
            status.setdefault("counts", {}).update(counts)
        temp = status_path.with_suffix(".json.tmp")
        temp.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(status_path)

    def worker() -> None:
        try:
            update_status("RUNNING", "正在重试 LLM 错误单元")
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"\n[{now()}] 开始重试 LLM 错误单元 ({input_csv})\n")
                log.flush()
                subprocess.run(cmd, env=env, cwd=str(base), check=False,
                               stdout=log, stderr=subprocess.STDOUT)
            summary_path = base / "triage_summary.json"
            if summary_path.is_file():
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                verdicts = summary.get("verdict_counts", {})
                errors = int(summary.get("status_counts", {}).get("error", 0))
                counts = {
                    "safe": int(verdicts.get("safe", 0)),
                    "dangerous": int(verdicts.get("vulnerability", 0)),
                    "manual": int(verdicts.get("need_manual", 0)),
                    "errors": errors,
                    "review_errors": errors,
                    "total_tokens": int(summary.get("total_tokens", 0)),
                    "input_tokens": int(summary.get("total_input_tokens", 0)),
                    "output_tokens": int(summary.get("total_output_tokens", 0)),
                }
                update_status("PASSED" if errors == 0 else "PARTIAL",
                              f"重试完成，剩余错误 {errors}", counts)
                with log_path.open("a", encoding="utf-8") as log:
                    log.write(f"[{now()}] 重试完成：剩余错误 {errors}\n")
                append_event(task, "codeql_retry_errors", {"errors": errors})
            else:
                update_status("PARTIAL", "重试结束但未生成 triage_summary.json")
        except Exception as exc:
            update_status("PARTIAL", f"重试失败：{exc}")
            try:
                with log_path.open("a", encoding="utf-8") as log:
                    log.write(f"[{now()}] 重试异常：{exc}\n")
            except OSError:
                pass

    append_event(task, "codeql_retry_started", {})
    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True, "started": True}


def report_task(task_id: str, payload: dict) -> dict:
    task = get_task(task_id)
    if not task:
        raise KeyError("任务不存在")
    allowed = {"stage", "status", "probe_modes", "validation", "static_analysis", "codeql_query", "metrics", "fuzz", "seed", "cycle", "message"}
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"不支持的上报字段：{', '.join(sorted(unknown))}")
    report_path = task_dir(task) / "snapshot" / "report.json"
    current = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    current = merge_dict(current, payload)
    current["updated_at"] = now()
    temp = report_path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(report_path)
    updates, params = [], []
    if payload.get("stage"):
        updates.append("stage=?"); params.append(str(payload["stage"]))
    if payload.get("status"):
        updates.append("status=?"); params.append(str(payload["status"]))
    if updates:
        params.append(task_id)
        with db() as conn:
            conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id=?", params)
    append_event(get_task(task_id), "workflow_report", {"fields": sorted(payload.keys())})
    updated = get_task(task_id)
    validation = payload.get("validation", {})
    # The bundled workflow runner reports a completed Probe stage as PASSED,
    # while the README/API contract also allows COMPLETED and READY_FOR_FUZZ.
    # Treat all three as terminal Probe success states so the real runner and
    # the web API use the same protocol.
    ready = payload.get("status") in {"PASSED", "COMPLETED", "READY_FOR_FUZZ"}
    if validation:
        ready = ready or all(
            validation.get(key, {}).get("status") in {"PASSED", "SKIPPED"}
            for key in ("driver_binding", "sysfs_interfaces", "open_test")
        )
    if updated["task_type"] == "PROBE" and ready:
        completed = completed_probe_metadata(updated["linux_version"], updated["driver"])
        record_probe_completion(
            updated["linux_version"], completed.pop("name"),
            linux_path=completed.pop("linux_path"),
            type_tags=completed.pop("type_tags"),
            vid=completed.pop("vid"), pid=completed.pop("pid"),
            subvid=completed.pop("subvid", ""), subpid=completed.pop("subpid", ""),
            path=PROBE_COMPLETED_TARGETS)
        # Keep the historical B.json interface synchronized for existing tools.
        add_target(FUZZ_TARGETS, updated["linux_version"], updated["driver"])
        append_event(updated, "fuzz_target_unlocked", {"linux_version": updated["linux_version"], "driver": updated["driver"]})
    seed_finished = payload.get("seed", {}).get("status") == "COMPLETED"
    if updated["task_type"] == "FUZZ" and (payload.get("status") == "COMPLETED" or seed_finished):
        add_target(SEED_TARGETS, updated["linux_version"], updated["driver"])
        append_event(updated, "seed_target_unlocked", {"linux_version": updated["linux_version"], "driver": updated["driver"]})
    return get_task(task_id)


class Handler(SimpleHTTPRequestHandler):
    server_version = "SyzkallerWorkbench/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{now()}] {self.address_string()} {fmt % args}")

    def end_headers(self) -> None:
        path = self.path.split("?", 1)[0]
        if path.endswith((".js", ".css", ".html")):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, value, status=200) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, target: Path, download_name: str) -> None:
        if not target.is_file():
            return self.send_json({"error": "结果文件不存在"}, 404)
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == '/api/pipelines':
            return self.send_json({'items': PIPELINES.list()})
        if path == "/api/health":
            return self.send_json({"ok": True, "offline": True, "time": now(), "configured": PIPELINES is not None})
        if path == "/api/system":
            cfg = config()
            codeql = cfg.get("codeql_query", {})
            return self.send_json({"offline": True, "manager_port_range": cfg["manager_port_range"], "fuzz_cycle": cfg.get("fuzz_cycle", {}), "workflow_configured": PIPELINES is not None, "codeql": {"path": codeql.get("codeql_path", ""), "database_root": codeql.get("database_root", ""), "configured": bool(codeql.get("codeql_path") and codeql.get("database_root"))}, "llm": llm_settings()})
        if path == "/api/catalogs/probe":
            ready, unavailable = driver_catalog_with_reasons()
            return self.send_json({"items": ready, "unavailable": unavailable})
        if path == "/api/catalogs/static":
            ready, unavailable = driver_catalog_with_reasons()
            return self.send_json({"items": ready, "unavailable": unavailable})
        if path == "/api/catalogs/fuzz":
            return self.send_json({"items": fuzz_catalog()})
        if path == "/api/catalogs/seed":
            return self.send_json({"items": read_catalog(SEED_TARGETS)})
        if path == "/api/catalogs/codeql":
            return self.send_json(codeql_catalog())
        if path == "/api/pipeline/targets":
            try:
                limit = int(query.get("limit", ["50"])[0])
                offset = int(query.get("offset", ["0"])[0])
            except ValueError:
                return self.send_json({"error": "分页参数必须是整数"}, 400)
            return self.send_json(pipeline_targets(
                query.get("linux", [""])[0], query.get("q", [""])[0], limit, offset))
        if path == "/api/tasks":
            return self.send_json({"items": list_tasks()})
        match = re.fullmatch(r"/api/tasks/([^/]+)", path)
        if match:
            task = get_task(unquote(match.group(1)))
            return self.send_json(task or {"error": "任务不存在"}, 200 if task else 404)
        match = re.fullmatch(r"/api/tasks/([^/]+)/telemetry", path)
        if match:
            task = get_task(unquote(match.group(1)))
            if not task or task['task_type'] != 'FUZZ':
                return self.send_json({'error': 'Fuzz 任务不存在'}, 404)
            telemetry = read_telemetry(task_dir(task))
            telemetry['started_at'] = task.get('started_at')
            telemetry['finished_at'] = task.get('finished_at')
            telemetry['task_status'] = task['status']
            telemetry['pipeline'] = next(({
                'round': item.get('round'), 'stage': item.get('stage'),
                'status': item.get('status'), 'elapsed_seconds': item.get('elapsed_seconds')
            } for item in PIPELINES.list() if task['id'] in item.get('tasks', [])), None) if PIPELINES else None
            return self.send_json(telemetry)
        match = re.fullmatch(r"/api/tasks/([^/]+)/logs", path)
        if match:
            task = get_task(unquote(match.group(1)))
            if not task:
                return self.send_json({"error": "任务不存在"}, 404)
            log = task_dir(task) / "logs" / "workflow.log"
            text = log.read_text(encoding="utf-8", errors="replace")[-100000:] if log.exists() else ""
            return self.send_json({"content": text})
        match = re.fullmatch(r"/api/tasks/([^/]+)/logs/(static|fuzz|seed|codeql|workflow)", path)
        if match:
            task = get_task(unquote(match.group(1)))
            if not task:
                return self.send_json({"error": "任务不存在"}, 404)
            name = match.group(2)
            log_dir = task_dir(task) / "logs"
            filenames = {
                "static": ["svf.log", "collector.log"],
                "fuzz": ["fuzz.log"],
                "seed": ["seed.log"],
                "codeql": ["workflow.log"],
                "workflow": ["workflow.log"],
            }[name]
            sections = []
            for filename in filenames:
                target = log_dir / filename
                if target.exists():
                    sections.append(f"===== {filename} =====\n" + target.read_text(encoding="utf-8", errors="replace")[-100000:])
            return self.send_json({"content": "\n\n".join(sections)})
        match = re.fullmatch(r"/api/tasks/([^/]+)/codeql-result", path)
        if match:
            task = get_task(unquote(match.group(1)))
            if not task or task["task_type"] != "CODEQL_QUERY":
                return self.send_json({"error": "CodeQL 查询任务不存在"}, 404)
            result = task_dir(task) / "artifacts" / "codeql" / "merged_semantic_unique.csv"
            return self.send_file(result, f"{task['linux_version']}_{task['driver']}_codeql.csv")
        match = re.fullmatch(r"/api/tasks/([^/]+)/events", path)
        if match:
            task = get_task(unquote(match.group(1)))
            if not task:
                return self.send_json({"error": "任务不存在"}, 404)
            target = task_dir(task) / "events.jsonl"
            items = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()] if target.exists() else []
            return self.send_json({"items": items[-200:]})
        if path.startswith("/api/"):
            return self.send_json({"error": "接口不存在"}, 404)
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == '/api/pipelines':
                return self.send_json(PIPELINES.create(self.body()), 201)
            pipeline_match = re.fullmatch(r'/api/pipelines/([^/]+)/(stop|release)', path)
            if pipeline_match:
                key, action = pipeline_match.groups()
                return self.send_json(PIPELINES.stop(key) if action == 'stop' else PIPELINES.release(key, self.body().get('confirmed')))
            if path == "/api/tasks":
                return self.send_json(create_task(self.body()), 201)
            if path == "/api/system/llm":
                return self.send_json(save_llm_settings(self.body()))
            match = re.fullmatch(r"/api/tasks/([^/]+)/(start|stop)", path)
            if match:
                task_id, action = unquote(match.group(1)), match.group(2)
                result = start_task(task_id) if action == "start" else stop_task(task_id)
                return self.send_json(result)
            match = re.fullmatch(r"/api/tasks/([^/]+)/seed", path)
            if match:
                seed = create_task({"task_type": "SEED", "parent_task_id": unquote(match.group(1))})
                return self.send_json(seed, 201)
            match = re.fullmatch(r"/api/tasks/([^/]+)/report", path)
            if match:
                return self.send_json(report_task(unquote(match.group(1)), self.body()))
            match = re.fullmatch(r"/api/tasks/([^/]+)/codeql-retry-errors", path)
            if match:
                task = get_task(unquote(match.group(1)))
                if not task or task["task_type"] != "CODEQL_QUERY":
                    return self.send_json({"error": "CodeQL 查询任务不存在"}, 404)
                return self.send_json(start_codeql_error_retry(task))
            return self.send_json({"error": "接口不存在"}, 404)
        except (ValueError, RuntimeError) as exc:
            return self.send_json({"error": str(exc)}, 409)
        except KeyError as exc:
            return self.send_json({"error": str(exc)}, 404)
        except Exception as exc:
            return self.send_json({"error": f"服务器错误：{exc}"}, 500)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        try:
            match = re.fullmatch(r"/api/tasks/([^/]+)", path)
            if match:
                return self.send_json(delete_task(unquote(match.group(1))))
            return self.send_json({"error": "接口不存在"}, 404)
        except RuntimeError as exc:
            return self.send_json({"error": str(exc)}, 409)
        except KeyError as exc:
            return self.send_json({"error": str(exc)}, 404)
        except Exception as exc:
            return self.send_json({"error": f"服务器错误：{exc}"}, 500)

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else unquote(path).lstrip("/")
        target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents and target != STATIC.resolve():
            return self.send_error(403)
        if not target.exists() or not target.is_file():
            target = STATIC / "index.html"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    init_storage()
    sync_codeql_llm_settings()
    cfg = config()
    address = (cfg.get("host", "127.0.0.1"), int(cfg.get("port", 8080)))
    print(f"Syzkaller Workbench offline: http://{address[0]}:{address[1]}")
    ThreadingHTTPServer(address, Handler).serve_forever()
