#!/usr/bin/env python3
"""Standalone CodeQL workflow for the Linux concurrency query package.

The runner creates or reuses a CodeQL database, executes the eight concurrency
queries plus the optional ops level-2 recall query, decodes CSV results, and
writes atomic status/artifact files. It is intentionally independent from the
workbench's existing runner so it can be deployed and tested without restart.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

OK = 0
INTERNAL = 1
CONFIG = 2
DATABASE = 3
QUERY = 4
DECODE = 5
MERGE = 6
CANCELLED = 130

QUERY_FILES = {
    "irq": "IRQ/concurrent_irq_free_use_fast_recall_v2_detail.ql",
    "hrtimer": "hrtimer/HrtimerConcurrentFreeFinal.ql",
    "kthread": "kthread/KthreadConcurrentUafFinal.ql",
    "napi": "NAPI/NapiConcurrentFreeFinal.ql",
    "rcu": "RCU/RcuConcurrentFreeFinal.ql",
    "tasklet": "tasklet/TaskletConcurrentFreeFinal.ql",
    "timer": "timer/TimerConcurrentFreeFinal.ql",
    "workqueue": "workqueue/WorkqueueConcurrentFinalDetail.ql",
    "ops": "ops/OpsLifetimeCandidates.ql",
}
CONCURRENCY_QUERIES = tuple(name for name in QUERY_FILES if name != "ops")


class WorkflowError(RuntimeError):
    def __init__(self, message: str, code: int, stage: str) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage


class WorkflowCancelled(RuntimeError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"无法读取配置文件: {path}: {exc}", CONFIG, "CONFIG") from exc
    if not isinstance(value, dict):
        raise WorkflowError("配置顶层必须是 JSON 对象", CONFIG, "CONFIG")
    return value


def path_value(config: Mapping[str, Any], name: str, base: Path, optional: bool = False) -> Path | None:
    value = config.get(name)
    if optional and (value is None or value == ""):
        return None
    if not isinstance(value, str) or not value.strip():
        raise WorkflowError(f"缺少或无效配置: {name}", CONFIG, "CONFIG")
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def integer(config: Mapping[str, Any], name: str, default: int) -> int:
    value = config.get(name, default)
    if isinstance(value, bool):
        raise WorkflowError(f"{name} 必须是整数", CONFIG, "CONFIG")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise WorkflowError(f"{name} 必须是整数", CONFIG, "CONFIG") from exc
    if result < 0:
        raise WorkflowError(f"{name} 不能为负数", CONFIG, "CONFIG")
    return result


def command_args(value: Any, name: str) -> list[str]:
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return list(value)
    if isinstance(value, str) and value.strip():
        return shlex.split(value)
    raise WorkflowError(f"{name} 必须是非空命令字符串或数组", CONFIG, "CONFIG")


def csv_count(path: Path) -> int:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        next(reader, None)
        return sum(1 for row in reader if any(cell.strip() for cell in row))


def finalized_database(path: Path) -> bool:
    metadata = path / "codeql-database.yml"
    if not metadata.is_file():
        return False
    text = metadata.read_text(encoding="utf-8", errors="replace")
    return "finalised: true" in text or "finalized: true" in text


class Workflow:
    def __init__(self, config: dict[str, Any], config_path: Path) -> None:
        self.config = config
        self.config_path = config_path.resolve()
        self.base = self.config_path.parent
        self.task_id = str(config.get("task_id") or self.config_path.stem)
        self.codeql = path_value(config, "codeql_path", self.base)
        self.query_root = path_value(config, "query_root", self.base, optional=True) or self.base
        self.database = path_value(config, "database_dir", self.base)
        self.output = path_value(config, "output_dir", self.base)
        assert self.codeql and self.database and self.output
        if self.codeql.is_dir() or not self.codeql.is_file():
            raise WorkflowError(f"CodeQL 可执行文件不存在: {self.codeql}", CONFIG, "CONFIG")
        self.threads = integer(config, "threads", 0)
        self.ram = integer(config, "ram_mb", 0)
        self.build_threads = integer(config, "build_threads", max(1, os.cpu_count() or 1))
        if self.build_threads == 0:
            raise WorkflowError("build_threads 必须大于 0", CONFIG, "CONFIG")
        selected = config.get("queries", list(QUERY_FILES))
        if not isinstance(selected, list) or not selected:
            raise WorkflowError("queries 必须是非空数组", CONFIG, "CONFIG")
        self.queries: list[str] = []
        for raw in selected:
            name = str(raw).strip().lower()
            if name not in QUERY_FILES:
                raise WorkflowError(f"不支持的查询: {raw}; 可选: {', '.join(QUERY_FILES)}", CONFIG, "CONFIG")
            if name not in self.queries:
                self.queries.append(name)
        self.bqrs = self.output / "bqrs"
        self.csv = self.output / "csv"
        self.status_file = self.output / "status.json"
        self.artifacts_file = self.output / "artifacts.json"
        self.log_file = self.output / "run.log"
        self.merged = self.output / "merged_semantic_unique.csv"
        self.output.mkdir(parents=True, exist_ok=True)
        self.bqrs.mkdir(exist_ok=True)
        self.csv.mkdir(exist_ok=True)
        self.log_stream = self.log_file.open("a", encoding="utf-8", buffering=1)
        self.created_database = False
        self.process: subprocess.Popen[str] | None = None
        self.cancel_requested = False
        progress = {name: ("PENDING" if name in self.queries else "SKIPPED") for name in QUERY_FILES}
        self.state: dict[str, Any] = {
            "task_id": self.task_id, "status": "PENDING", "stage": "INITIALIZING",
            "started_at": now(), "updated_at": now(), "finished_at": None,
            "progress": {"database": "PENDING", **progress, "merge": "PENDING"},
            "counts": {**{name: None for name in QUERY_FILES}, "merged": None},
            "failures": [], "message": "任务初始化", "result_file": None,
        }

    def close(self) -> None:
        self.log_stream.close()

    def log(self, level: str, message: str) -> None:
        line = f"[{now()}] [{level}] {message}"
        print(line, flush=True)
        self.log_stream.write(line + "\n")

    def status(self, **updates: Any) -> None:
        self.state.update(updates)
        self.state["updated_at"] = now()
        atomic_json(self.status_file, self.state)

    def run(self, argv: Sequence[str], cwd: Path | None = None) -> int:
        if self.cancel_requested:
            raise WorkflowCancelled()
        self.log("INFO", f"执行命令: {shlex.join(map(str, argv))}")
        kwargs: dict[str, Any] = {"cwd": str(cwd) if cwd else None, "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT, "text": True, "encoding": "utf-8", "errors": "replace",
            "bufsize": 1, "start_new_session": True}
        self.process = subprocess.Popen(list(argv), **kwargs)
        try:
            assert self.process.stdout
            for line in self.process.stdout:
                self.log_stream.write(line.rstrip("\r\n") + "\n")
                print(line.rstrip("\r\n"), flush=True)
            code = self.process.wait()
        finally:
            self.process = None
        if self.cancel_requested:
            raise WorkflowCancelled()
        self.log("INFO" if code == 0 else "ERROR", f"命令退出码: {code}")
        return code

    def cancel(self, signum: int) -> None:
        if self.cancel_requested:
            return
        self.cancel_requested = True
        self.log("WARN", f"收到终止信号 {signum}")
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            threading.Thread(target=self.kill_later, daemon=True).start()

    def kill_later(self) -> None:
        process = self.process
        if process is None:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    def validate(self) -> None:
        if self.output == Path(self.output.anchor) or self.database == Path(self.database.anchor):
            raise WorkflowError("output_dir/database_dir 不能是文件系统根目录", CONFIG, "CONFIG")
        if not self.query_root.is_dir():
            raise WorkflowError(f"查询目录不存在: {self.query_root}", CONFIG, "CONFIG")
        for name in self.queries:
            query = self.query_root / QUERY_FILES[name]
            if not query.is_file():
                raise WorkflowError(f"查询文件不存在: {query}", CONFIG, "CONFIG")

    def build_command(self) -> tuple[Path, str]:
        kernel = path_value(self.config, "kernel_root", self.base, optional=True)
        source = kernel or path_value(self.config, "source_dir", self.base, optional=True)
        if source is None or not source.is_dir():
            raise WorkflowError("创建数据库需要有效的 kernel_root 或 source_dir", CONFIG, "CONFIG")
        custom = self.config.get("build_command")
        if custom is not None:
            return source, shlex.join(command_args(custom, "build_command")) if isinstance(custom, list) else str(custom)
        make = str(self.config.get("make_command") or "make")
        argv = [make, "-C", str(source)]
        driver = path_value(self.config, "driver_dir", self.base)
        if kernel:
            if not driver.is_dir():
                raise WorkflowError(f"驱动目录不存在: {driver}", CONFIG, "CONFIG")
            argv.append(f"M={driver}")
        if self.config.get("arch"):
            argv.append(f"ARCH={self.config['arch']}")
        if self.config.get("cross_compile"):
            argv.append(f"CROSS_COMPILE={self.config['cross_compile']}")
        argv.append(f"-j{self.build_threads}")
        if kernel:
            argv.append(str(self.config.get("make_target") or "modules"))
        return source, shlex.join(["env", "CCACHE_DISABLE=1", *argv])

    def prepare_database(self) -> None:
        reuse = bool(self.config.get("reuse_database", True))
        overwrite = bool(self.config.get("overwrite_database", False))
        if self.database.exists():
            if overwrite:
                self.log("WARN", f"按任务配置覆盖已有数据库: {self.database}")
                self.state["progress"]["database"] = "OVERWRITE"
            elif reuse and finalized_database(self.database):
                self.log("INFO", f"复用已完成数据库: {self.database}")
                self.state["progress"]["database"] = "REUSED"
                self.status(stage="DATABASE", status="RUNNING", message="复用已完成数据库")
                return
            elif (self.database / "codeql-database.yml").is_file() and not finalized_database(self.database):
                # A failed CodeQL create leaves an explicitly non-finalised database.
                # It is safe to rebuild that stale database, but never auto-overwrite
                # a completed database or an unrelated directory.
                overwrite = True
                self.log("WARN", f"发现未完成 CodeQL 数据库，自动覆盖重建: {self.database}")
                self.state["progress"]["database"] = "OVERWRITE_STALE"
            elif not overwrite:
                raise WorkflowError(f"数据库目录已存在且不是可复用的已完成数据库: {self.database}", DATABASE, "DATABASE")
        source, command = self.build_command()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.state["progress"]["database"] = "RUNNING"
        self.status(stage="DATABASE", status="RUNNING", message="正在创建数据库")
        self.created_database = True
        argv = [str(self.codeql), "database", "create", str(self.database), "--language=cpp",
            f"--source-root={source}", f"--threads={self.threads}"]
        if self.ram:
            argv.append(f"--ram={self.ram}")
        argv.append(f"--command={command}")
        if overwrite:
            argv.append("--overwrite")
        if self.run(argv) != 0:
            self.state["progress"]["database"] = "FAILED"
            raise WorkflowError("CodeQL 数据库创建失败", DATABASE, "DATABASE")
        if not finalized_database(self.database):
            self.state["progress"]["database"] = "FAILED"
            raise WorkflowError("CodeQL 数据库创建命令结束但数据库未 finalised", DATABASE, "DATABASE")
        self.state["progress"]["database"] = "PASSED"
        self.status(stage="DATABASE", status="RUNNING", message="数据库创建完成")

    def run_one(self, name: str) -> Path:
        query = self.query_root / QUERY_FILES[name]
        bqrs = self.bqrs / f"{name}.bqrs"
        output = self.csv / f"{name}.csv"
        self.state["progress"][name] = "RUNNING"
        self.status(stage="QUERYING", status="RUNNING", message=f"正在执行 {name} 查询")
        argv = [str(self.codeql), "query", "run", f"--database={self.database}", f"--threads={self.threads}"]
        if self.ram:
            argv.append(f"--ram={self.ram}")
        argv += [f"--output={bqrs}", str(query)]
        if self.run(argv) != 0:
            self.state["progress"][name] = "FAILED"
            raise WorkflowError(f"{name} 查询失败", QUERY, "QUERYING")
        decode = [str(self.codeql), "bqrs", "decode", "--format=csv", f"--output={output}", str(bqrs)]
        self.status(stage="DECODING", message=f"正在解码 {name} 结果")
        if self.run(decode) != 0:
            self.state["progress"][name] = "FAILED"
            raise WorkflowError(f"{name} 结果解码失败", DECODE, "DECODING")
        count = csv_count(output)
        self.state["progress"][name] = "PASSED"
        self.state["counts"][name] = count
        self.log("INFO", f"{name} 查询完成: {count} 条")
        self.status(stage="QUERYING", message=f"{name} 查询完成: {count} 条")
        return output

    def merge(self, csv_files: list[Path]) -> None:
        if not csv_files:
            self.state["progress"]["merge"] = "SKIPPED"
            return
        script = self.query_root / "merge_concurrency_csv.py"
        if not script.is_file():
            raise WorkflowError(f"融合脚本不存在: {script}", MERGE, "MERGING")
        self.status(stage="MERGING", status="RUNNING", message="正在融合八个并发查询结果")
        argv = [sys.executable, str(script), *(str(path) for path in csv_files), "-o", str(self.merged)]
        if self.run(argv) != 0:
            self.state["progress"]["merge"] = "FAILED"
            raise WorkflowError("八个并发查询结果融合失败", MERGE, "MERGING")
        self.state["progress"]["merge"] = "PASSED"
        self.state["counts"]["merged"] = csv_count(self.merged)
        self.state["result_file"] = str(self.merged)

    def artifacts(self, status: str) -> None:
        files = []
        for path in sorted(self.csv.glob("*.csv")) + sorted(self.bqrs.glob("*.bqrs")):
            files.append({"path": str(path), "category": path.stem, "type": path.suffix[1:]})
        if self.merged.is_file():
            files.append({"path": str(self.merged), "category": "merged", "type": "csv"})
        atomic_json(self.artifacts_file, {"task_id": self.task_id, "status": status,
            "database_dir": str(self.database), "files": files, "generated_at": now()})

    def cleanup_created_database(self) -> None:
        if self.created_database and self.database.exists() and not finalized_database(self.database):
            import shutil
            self.log("WARN", f"清理本次创建的未完成数据库: {self.database}")
            shutil.rmtree(self.database)

    def execute(self) -> int:
        self.log("INFO", f"开始任务 {self.task_id}")
        self.status(status="RUNNING", stage="VALIDATING", message="正在校验配置")
        self.validate()
        self.prepare_database()
        outputs: dict[str, Path] = {}
        failures = []
        for name in self.queries:
            try:
                outputs[name] = self.run_one(name)
            except WorkflowError as exc:
                failures.append({"query": name, "stage": exc.stage, "error": str(exc)})
                self.state["failures"].append(failures[-1])
                self.log("ERROR", str(exc))
        if any(name in self.queries for name in CONCURRENCY_QUERIES):
            merge_inputs = [outputs[name] for name in CONCURRENCY_QUERIES if name in outputs and name in self.queries]
            try:
                self.merge(merge_inputs)
            except WorkflowError as exc:
                failures.append({"stage": exc.stage, "error": str(exc)})
                self.state["failures"].append(failures[-1])
        if failures:
            self.status(status="FAILED", stage="FINISHED", finished_at=now(), message="部分流程失败")
            self.artifacts("FAILED")
            return QUERY if any(item.get("stage") == "QUERYING" for item in failures) else INTERNAL
        self.status(status="COMPLETED", stage="FINISHED", finished_at=now(), message="流程完成")
        self.artifacts("COMPLETED")
        return OK

    def fail(self, exc: WorkflowError) -> int:
        self.cleanup_created_database()
        self.state["failures"].append({"stage": exc.stage, "error": str(exc), "exit_code": exc.code})
        self.status(status="FAILED", stage=exc.stage, finished_at=now(), message=str(exc))
        self.artifacts("FAILED")
        self.log("ERROR", str(exc))
        return exc.code


def example() -> dict[str, Any]:
    return {"task_id": "static_query_example", "codeql_path": "/media/iotteam/hd/lx/codeql/codeql",
        "kernel_root": "/media/iotteam/hd/pyh/mi/linux-7.1.5",
        "driver_dir": "/media/iotteam/hd/pyh/mi/linux-7.1.5/drivers/net/ethernet/3com",
        "query_root": str(Path(__file__).resolve().parent),
        "database_dir": "/media/iotteam/hd/lx/codeql-db/linux-7.1.5_example",
        "output_dir": "/media/iotteam/hd/lx/static-query-result/example", "reuse_database": True,
        "threads": 0, "ram_mb": 16000, "build_threads": 16, "arch": "x86_64",
        "queries": list(QUERY_FILES)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="独立 Linux 并发 CodeQL 工作流")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--config", type=Path)
    group.add_argument("--task-dir", type=Path)
    parser.add_argument("--task-id")
    parser.add_argument("--print-example-config", action="store_true")
    args = parser.parse_args(argv)
    if args.print_example_config:
        print(json.dumps(example(), ensure_ascii=False, indent=2))
        return OK
    if not args.config and not args.task_dir:
        parser.error("必须提供 --config 或 --task-dir")
    config_path = (args.task_dir / "snapshot/configs/static_query.json" if args.task_dir else args.config).resolve()
    try:
        config = read_json(config_path)
        if args.task_id:
            config["task_id"] = args.task_id
        runner = Workflow(config, config_path)
    except WorkflowError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return exc.code
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in previous:
        signal.signal(sig, lambda signum, _frame: runner.cancel(signum))
    try:
        return runner.execute()
    except WorkflowCancelled:
        runner.cleanup_created_database()
        runner.status(status="CANCELLED", stage="CANCELLED", finished_at=now(), message="任务已取消")
        runner.artifacts("CANCELLED")
        return CANCELLED
    except WorkflowError as exc:
        return runner.fail(exc)
    except Exception as exc:
        return runner.fail(WorkflowError(f"未处理的内部错误: {exc}", INTERNAL, "INTERNAL"))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        runner.close()


if __name__ == "__main__":
    raise SystemExit(main())
