#!/usr/bin/env python3
"""Single entry point for the Linux concurrency CodeQL query package.

The web backend can create a JSON configuration and execute either:

    python3 run_static_query.py --config /path/to/task_config.json

or the stable task-directory interface:

    python3 run_static_query.py --task-id <id> --task-dir <task_dir>

The latter reads ``<task_dir>/snapshot/configs/static_query.json``.

This program owns the CodeQL/build child processes, writes status atomically,
streams logs, retains successful partial CSV files, and emits an artifact list.
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


EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_CONFIG = 2
EXIT_DATABASE = 3
EXIT_QUERY = 4
EXIT_DECODE = 5
EXIT_MERGE = 6
EXIT_CANCELLED = 130

QUERY_FILES: dict[str, str] = {
    "irq": "IRQ/concurrent_irq_free_use_fast_recall_v2_detail.ql",
    "hrtimer": "hrtimer/HrtimerConcurrentFreeFinal.ql",
    "kthread": "kthread/KthreadConcurrentUafFinal.ql",
    "napi": "NAPI/NapiConcurrentFreeFinal.ql",
    "rcu": "RCU/RcuConcurrentFreeFinal.ql",
    "tasklet": "tasklet/TaskletConcurrentFreeFinal.ql",
    "timer": "timer/TimerConcurrentFreeFinal.ql",
    "workqueue": "workqueue/WorkqueueConcurrentFinalDetail.ql",
}


class TaskError(RuntimeError):
    def __init__(self, message: str, exit_code: int, stage: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stage = stage


class TaskCancelled(RuntimeError):
    pass


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise TaskError(f"无法读取配置文件 {path}: {exc}", EXIT_CONFIG, "CONFIG") from exc
    if not isinstance(value, dict):
        raise TaskError("配置文件顶层必须是 JSON 对象", EXIT_CONFIG, "CONFIG")
    return value


def resolve_path(value: Any, field: str, base: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise TaskError(f"缺少或无效的配置字段: {field}", EXIT_CONFIG, "CONFIG")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def optional_path(value: Any, field: str, base: Path) -> Path | None:
    if value is None or value == "":
        return None
    return resolve_path(value, field, base)


def reject_filesystem_root(path: Path, field: str) -> None:
    if path == Path(path.anchor):
        raise TaskError(f"{field} 不能是文件系统根目录: {path}", EXIT_CONFIG, "CONFIG")


def integer_option(config: Mapping[str, Any], name: str, default: int) -> int:
    value = config.get(name, default)
    if isinstance(value, bool):
        raise TaskError(f"{name} 必须是整数", EXIT_CONFIG, "CONFIG")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise TaskError(f"{name} 必须是整数", EXIT_CONFIG, "CONFIG") from exc


def command_prefix(config: Mapping[str, Any], base: Path) -> list[str]:
    custom = config.get("codeql_command")
    if custom is not None:
        if not isinstance(custom, list) or not custom or not all(
            isinstance(item, str) and item for item in custom
        ):
            raise TaskError("codeql_command 必须是非空字符串数组", EXIT_CONFIG, "CONFIG")
        return list(custom)
    codeql = resolve_path(config.get("codeql_path"), "codeql_path", base)
    if not codeql.is_file():
        raise TaskError(f"CodeQL 不存在: {codeql}", EXIT_CONFIG, "CONFIG")
    return [str(codeql)]


def argv_from_config(value: Any, field: str) -> list[str]:
    if isinstance(value, str) and value.strip():
        return shlex.split(value)
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return list(value)
    raise TaskError(f"{field} 必须是命令字符串或非空字符串数组", EXIT_CONFIG, "CONFIG")


def count_csv_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for row in reader if any(cell.strip() for cell in row))


class StaticQueryRunner:
    def __init__(self, config: dict[str, Any], config_path: Path) -> None:
        self.config = config
        self.config_path = config_path
        self.config_base = config_path.parent.resolve()
        self.script_root = Path(__file__).resolve().parent

        self.task_id = str(config.get("task_id") or config_path.stem)
        self.output_dir = resolve_path(config.get("output_dir"), "output_dir", self.config_base)
        self.database_dir = resolve_path(
            config.get("database_dir"), "database_dir", self.config_base
        )
        reject_filesystem_root(self.output_dir, "output_dir")
        reject_filesystem_root(self.database_dir, "database_dir")
        self.query_root = optional_path(
            config.get("query_root"), "query_root", self.config_base
        ) or self.script_root
        self.merge_script = optional_path(
            config.get("merge_script"), "merge_script", self.config_base
        ) or (self.query_root / "merge_concurrency_csv.py")

        self.codeql = command_prefix(config, self.config_base)
        self.threads = integer_option(config, "threads", 0)
        self.ram_mb = integer_option(config, "ram_mb", 0)
        self.build_threads = integer_option(
            config, "build_threads", max(1, os.cpu_count() or 1)
        )
        if self.build_threads <= 0:
            raise TaskError("build_threads 必须大于 0", EXIT_CONFIG, "CONFIG")

        configured_queries = config.get("queries", list(QUERY_FILES))
        if not isinstance(configured_queries, list) or not configured_queries:
            raise TaskError("queries 必须是非空数组", EXIT_CONFIG, "CONFIG")
        self.queries: list[str] = []
        for value in configured_queries:
            name = str(value).strip().lower()
            if name not in QUERY_FILES:
                raise TaskError(
                    f"不支持的查询 {value!r}; 可选值: {', '.join(QUERY_FILES)}",
                    EXIT_CONFIG,
                    "CONFIG",
                )
            if name not in self.queries:
                self.queries.append(name)

        self.bqrs_dir = self.output_dir / "bqrs"
        self.csv_dir = self.output_dir / "csv"
        self.status_path = self.output_dir / "status.json"
        self.artifacts_path = self.output_dir / "artifacts.json"
        self.log_path = self.output_dir / "run.log"
        self.merged_csv = self.output_dir / "merged_semantic_unique.csv"

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.bqrs_dir.mkdir(parents=True, exist_ok=True)
        self.csv_dir.mkdir(parents=True, exist_ok=True)
        self.log_handle = self.log_path.open("a", encoding="utf-8", buffering=1)

        progress = {name: "PENDING" for name in QUERY_FILES}
        for name in QUERY_FILES:
            if name not in self.queries:
                progress[name] = "SKIPPED"
        progress = {"database": "PENDING", **progress, "merge": "PENDING"}
        self.state: dict[str, Any] = {
            "task_id": self.task_id,
            "status": "PENDING",
            "stage": "INITIALIZING",
            "started_at": now_iso(),
            "updated_at": now_iso(),
            "finished_at": None,
            "progress": progress,
            "counts": {**{name: None for name in QUERY_FILES}, "merged": None},
            "message": "任务初始化",
            "result_file": None,
            "failures": [],
        }
        self.artifacts: list[dict[str, Any]] = []
        self.current_process: subprocess.Popen[str] | None = None
        self.cancel_requested = False

    def close(self) -> None:
        self.log_handle.close()

    def log(self, level: str, message: str) -> None:
        line = f"[{now_iso()}] [{level}] {message}"
        print(line, flush=True)
        self.log_handle.write(line + "\n")

    def write_status(self, **updates: Any) -> None:
        self.state.update(updates)
        self.state["updated_at"] = now_iso()
        atomic_write_json(self.status_path, self.state)

    def write_artifacts(self, final_status: str) -> None:
        value = {
            "task_id": self.task_id,
            "status": final_status,
            "database_dir": str(self.database_dir),
            "merged_csv": str(self.merged_csv) if self.merged_csv.is_file() else None,
            "files": self.artifacts,
            "generated_at": now_iso(),
        }
        atomic_write_json(self.artifacts_path, value)

    def request_cancel(self, signum: int) -> None:
        if self.cancel_requested:
            return
        self.cancel_requested = True
        self.log("WARN", f"收到终止信号 {signum}，正在停止当前子进程")
        process = self.current_process
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            return

        def force_kill() -> None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass

        threading.Thread(target=force_kill, daemon=True).start()

    def check_cancelled(self) -> None:
        if self.cancel_requested:
            raise TaskCancelled("任务已取消")

    def run_command(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> int:
        self.check_cancelled()
        rendered = shlex.join(str(item) for item in argv)
        self.log("INFO", f"执行命令: {rendered}")
        popen_kwargs: dict[str, Any] = {
            "cwd": str(cwd) if cwd else None,
            "env": dict(env) if env else None,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "bufsize": 1,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        process = subprocess.Popen(list(argv), **popen_kwargs)
        self.current_process = process
        try:
            assert process.stdout is not None
            for raw_line in process.stdout:
                line = raw_line.rstrip("\r\n")
                print(line, flush=True)
                self.log_handle.write(line + "\n")
                if self.cancel_requested and process.poll() is None:
                    self.request_cancel(signal.SIGTERM)
            return_code = process.wait()
        finally:
            self.current_process = None
        self.check_cancelled()
        self.log("INFO" if return_code == 0 else "ERROR", f"命令退出码: {return_code}")
        return return_code

    def validate(self) -> None:
        if not self.query_root.is_dir():
            raise TaskError(f"查询目录不存在: {self.query_root}", EXIT_CONFIG, "CONFIG")
        if not self.merge_script.is_file():
            raise TaskError(f"融合脚本不存在: {self.merge_script}", EXIT_CONFIG, "CONFIG")
        for name in self.queries:
            path = self.query_root / QUERY_FILES[name]
            if not path.is_file():
                raise TaskError(f"查询文件不存在: {path}", EXIT_CONFIG, "CONFIG")

    def codeql_resource_options(self) -> list[str]:
        options = [f"--threads={self.threads}"]
        if self.ram_mb > 0:
            options.append(f"--ram={self.ram_mb}")
        return options

    def generated_build_command(self) -> tuple[Path, str]:
        custom = self.config.get("build_command")
        kernel_root = optional_path(
            self.config.get("kernel_root"), "kernel_root", self.config_base
        )
        source_dir = optional_path(
            self.config.get("source_dir"), "source_dir", self.config_base
        )
        source_root = kernel_root or source_dir
        if source_root is None:
            raise TaskError(
                "创建数据库需要 kernel_root 或 source_dir", EXIT_CONFIG, "CONFIG"
            )
        if not source_root.is_dir():
            raise TaskError(f"源码目录不存在: {source_root}", EXIT_CONFIG, "CONFIG")

        if custom is not None:
            if isinstance(custom, list):
                command = shlex.join(argv_from_config(custom, "build_command"))
            elif isinstance(custom, str) and custom.strip():
                command = custom
            else:
                raise TaskError("build_command 格式无效", EXIT_CONFIG, "CONFIG")
            return source_root, command

        make_command = str(self.config.get("make_command") or "make")
        argv = [make_command, "-C", str(source_root)]
        raw_driver_dir = self.config.get("driver_dir")
        if raw_driver_dir is None or raw_driver_dir == "":
            driver_dir = None
        elif not isinstance(raw_driver_dir, str):
            raise TaskError("driver_dir 必须是路径字符串", EXIT_CONFIG, "CONFIG")
        else:
            candidate = Path(raw_driver_dir).expanduser()
            if not candidate.is_absolute() and kernel_root is not None:
                candidate = kernel_root / candidate
            elif not candidate.is_absolute():
                candidate = self.config_base / candidate
            driver_dir = candidate.resolve()
        if kernel_root is not None:
            if driver_dir is None:
                raise TaskError(
                    "使用 kernel_root 自动生成构建命令时必须提供 driver_dir",
                    EXIT_CONFIG,
                    "CONFIG",
                )
            if not driver_dir.is_dir():
                raise TaskError(f"驱动目录不存在: {driver_dir}", EXIT_CONFIG, "CONFIG")
            argv.append(f"M={driver_dir}")
        arch = self.config.get("arch")
        cross_compile = self.config.get("cross_compile")
        if arch:
            argv.append(f"ARCH={arch}")
        if cross_compile:
            argv.append(f"CROSS_COMPILE={cross_compile}")
        argv.extend([f"-j{self.build_threads}"])
        if kernel_root is not None:
            argv.append(str(self.config.get("make_target") or "modules"))
        return source_root, shlex.join(["env", "CCACHE_DISABLE=1", *argv])

    def prepare_database(self) -> None:
        reuse = bool(self.config.get("reuse_database", False))
        valid_database = (self.database_dir / "codeql-database.yml").is_file()
        if reuse and valid_database:
            self.log("INFO", f"复用现有数据库: {self.database_dir}")
            self.state["progress"]["database"] = "REUSED"
            self.write_status(
                status="RUNNING", stage="DATABASE", message="复用现有 CodeQL 数据库"
            )
            return
        if reuse and self.database_dir.exists() and not valid_database:
            raise TaskError(
                f"reuse_database=true，但目录不是有效 CodeQL 数据库: {self.database_dir}",
                EXIT_DATABASE,
                "DATABASE",
            )

        self.state["progress"]["database"] = "RUNNING"
        self.write_status(status="RUNNING", stage="DATABASE", message="正在创建数据库")

        prepare_commands = self.config.get("prepare_commands", [])
        if not isinstance(prepare_commands, list):
            raise TaskError("prepare_commands 必须是命令数组", EXIT_CONFIG, "CONFIG")
        for index, value in enumerate(prepare_commands, start=1):
            argv = argv_from_config(value, f"prepare_commands[{index}]")
            self.log("INFO", f"执行准备命令 {index}")
            if self.run_command(argv) != 0:
                self.state["progress"]["database"] = "FAILED"
                raise TaskError("内核准备命令失败", EXIT_DATABASE, "DATABASE")

        source_root, build_command = self.generated_build_command()
        self.database_dir.parent.mkdir(parents=True, exist_ok=True)
        argv = [
            *self.codeql,
            "database",
            "create",
            str(self.database_dir),
            "--language=cpp",
            f"--source-root={source_root}",
            *self.codeql_resource_options(),
            f"--command={build_command}",
        ]
        if self.config.get("overwrite_database", False):
            argv.append("--overwrite")
        elif self.database_dir.exists():
            self.state["progress"]["database"] = "FAILED"
            raise TaskError(
                f"数据库目录已存在；请设置 reuse_database 或 overwrite_database: {self.database_dir}",
                EXIT_DATABASE,
                "DATABASE",
            )
        if self.run_command(argv) != 0:
            self.state["progress"]["database"] = "FAILED"
            raise TaskError("CodeQL 数据库创建失败", EXIT_DATABASE, "DATABASE")
        self.state["progress"]["database"] = "PASSED"
        self.write_status(status="RUNNING", stage="DATABASE", message="数据库创建完成")

    def install_pack_if_requested(self) -> None:
        if not self.config.get("install_query_pack", False):
            return
        self.write_status(status="RUNNING", stage="ENVIRONMENT", message="安装查询包依赖")
        if self.run_command([*self.codeql, "pack", "install", str(self.query_root)]) != 0:
            raise TaskError("CodeQL 查询包依赖安装失败", EXIT_CONFIG, "ENVIRONMENT")

    def run_queries(self) -> tuple[list[Path], int | None]:
        successful_csvs: list[Path] = []
        failure_exit: int | None = None
        for name in self.queries:
            self.check_cancelled()
            query = self.query_root / QUERY_FILES[name]
            bqrs = self.bqrs_dir / f"{name}.bqrs"
            output_csv = self.csv_dir / f"{name}.csv"
            self.state["progress"][name] = "RUNNING"
            self.write_status(
                status="RUNNING", stage="QUERYING", message=f"正在执行 {name} 查询"
            )
            self.log("INFO", f"运行 {name} 查询")
            argv = [
                *self.codeql,
                "query",
                "run",
                f"--database={self.database_dir}",
                *self.codeql_resource_options(),
                f"--output={bqrs}",
                str(query),
            ]
            if self.run_command(argv) != 0:
                failure_exit = failure_exit or EXIT_QUERY
                self.state["progress"][name] = "FAILED"
                self.state["failures"].append({"query": name, "stage": "QUERYING"})
                self.write_status(message=f"{name} 查询失败，继续其他查询")
                continue

            self.artifacts.append({"type": "bqrs", "category": name, "path": str(bqrs)})
            self.write_status(stage="DECODING", message=f"正在解码 {name} 查询结果")
            decode = [
                *self.codeql,
                "bqrs",
                "decode",
                "--format=csv",
                f"--output={output_csv}",
                str(bqrs),
            ]
            if self.run_command(decode) != 0:
                failure_exit = failure_exit or EXIT_DECODE
                self.state["progress"][name] = "FAILED"
                self.state["failures"].append({"query": name, "stage": "DECODING"})
                self.write_status(message=f"{name} 结果解码失败，继续其他查询")
                continue

            try:
                count = count_csv_rows(output_csv)
            except OSError as exc:
                failure_exit = failure_exit or EXIT_DECODE
                self.state["progress"][name] = "FAILED"
                self.state["failures"].append(
                    {"query": name, "stage": "DECODING", "error": str(exc)}
                )
                continue
            self.state["progress"][name] = "PASSED"
            self.state["counts"][name] = count
            successful_csvs.append(output_csv)
            self.artifacts.append(
                {"type": "csv", "category": name, "path": str(output_csv)}
            )
            self.log("INFO", f"{name} 查询完成: {count} 条")
            self.write_status(stage="QUERYING", message=f"{name} 查询完成: {count} 条")
        return successful_csvs, failure_exit

    def merge_results(self, csv_files: Sequence[Path]) -> None:
        if not csv_files:
            self.state["progress"]["merge"] = "SKIPPED"
            self.write_status(stage="MERGING", message="没有可融合的 CSV")
            return
        self.state["progress"]["merge"] = "RUNNING"
        self.write_status(status="RUNNING", stage="MERGING", message="正在融合查询结果")
        argv = [
            sys.executable,
            str(self.merge_script),
            *(str(path) for path in csv_files),
            "-o",
            str(self.merged_csv),
        ]
        if self.run_command(argv) != 0:
            self.state["progress"]["merge"] = "FAILED"
            raise TaskError("CSV 融合失败", EXIT_MERGE, "MERGING")
        try:
            count = count_csv_rows(self.merged_csv)
        except OSError as exc:
            self.state["progress"]["merge"] = "FAILED"
            raise TaskError(f"无法读取融合结果: {exc}", EXIT_MERGE, "MERGING") from exc
        self.state["progress"]["merge"] = "PASSED"
        self.state["counts"]["merged"] = count
        self.state["result_file"] = str(self.merged_csv)
        self.artifacts.append(
            {"type": "csv", "category": "merged", "path": str(self.merged_csv)}
        )
        self.log("INFO", f"融合完成: {count} 条")

    def cleanup_cancelled_bqrs(self) -> None:
        for path in self.bqrs_dir.glob("*.bqrs"):
            try:
                path.unlink()
            except OSError as exc:
                self.log("WARN", f"无法清理临时文件 {path}: {exc}")

    def execute(self) -> int:
        self.log("INFO", f"开始任务 {self.task_id}")
        self.write_status(status="RUNNING", stage="VALIDATING", message="正在校验配置")
        self.validate()
        self.install_pack_if_requested()
        self.prepare_database()
        successful, query_failure = self.run_queries()
        self.merge_results(successful)

        finished = now_iso()
        if query_failure is not None:
            message = "部分查询失败；已保留成功结果"
            self.write_status(
                status="FAILED",
                stage="FINISHED",
                finished_at=finished,
                message=message,
            )
            self.write_artifacts("FAILED")
            self.log("ERROR", message)
            return query_failure

        self.write_status(
            status="COMPLETED",
            stage="FINISHED",
            finished_at=finished,
            message="全部查询和融合完成",
        )
        self.write_artifacts("COMPLETED")
        self.log("INFO", "任务完成")
        return EXIT_OK

    def fail(self, error: TaskError) -> int:
        self.state["failures"].append(
            {"stage": error.stage, "error": str(error), "exit_code": error.exit_code}
        )
        self.write_status(
            status="FAILED",
            stage=error.stage,
            finished_at=now_iso(),
            message=str(error),
        )
        self.write_artifacts("FAILED")
        self.log("ERROR", str(error))
        return error.exit_code

    def cancelled(self) -> int:
        self.cleanup_cancelled_bqrs()
        self.write_status(
            status="CANCELLED",
            stage="CANCELLED",
            finished_at=now_iso(),
            message="任务已取消",
        )
        self.write_artifacts("CANCELLED")
        self.log("WARN", "任务已取消")
        return EXIT_CANCELLED


def example_config() -> dict[str, Any]:
    return {
        "task_id": "static_query_linux-7.1.5_irdma_001",
        "codeql_path": "/media/iotteam/hd/lx/codeql/codeql",
        "kernel_root": "/media/iotteam/hd/pyh/mi/linux-7.1.5",
        "driver_dir": "/media/iotteam/hd/pyh/mi/linux-7.1.5/drivers/infiniband/hw/irdma",
        "query_root": "/media/iotteam/hd/lx/static-query",
        "database_dir": "/media/iotteam/hd/lx/codeql-db/linux-7.1.5_irdma",
        "output_dir": "/media/iotteam/hd/lx/static-query-result/linux-7.1.5_irdma_001",
        "reuse_database": True,
        "overwrite_database": False,
        "install_query_pack": False,
        "threads": 0,
        "ram_mb": 16000,
        "build_threads": 16,
        "arch": "x86_64",
        "prepare_commands": [],
        "queries": ["irq", "hrtimer", "kthread", "napi", "rcu", "tasklet", "timer", "workqueue"],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Linux 并发释放 CodeQL 统一执行入口")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--config", type=Path, help="任务 JSON 配置文件")
    source.add_argument(
        "--task-dir",
        type=Path,
        help="任务目录；配置固定读取 snapshot/configs/static_query.json",
    )
    parser.add_argument("--task-id", help="网页任务 ID；使用 --task-dir 时必须提供")
    parser.add_argument(
        "--print-example-config",
        action="store_true",
        help="打印示例 JSON 配置并退出",
    )
    args = parser.parse_args(argv)
    if not args.print_example_config and args.config is None and args.task_dir is None:
        parser.error("必须提供 --config，或同时提供 --task-id 和 --task-dir")
    if args.task_dir is not None and not args.task_id:
        parser.error("使用 --task-dir 时必须提供 --task-id")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.print_example_config:
        json.dump(example_config(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return EXIT_OK

    if args.task_dir is not None:
        task_dir = args.task_dir.expanduser().resolve()
        config_path = task_dir / "snapshot" / "configs" / "static_query.json"
    else:
        config_path = args.config.expanduser().resolve()
    try:
        config = load_json(config_path)
        if args.task_id:
            config["task_id"] = args.task_id
        runner = StaticQueryRunner(config, config_path)
    except TaskError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return exc.exit_code

    previous_handlers: dict[int, Any] = {}

    def signal_handler(signum: int, _frame: Any) -> None:
        runner.request_cancel(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, signal_handler)

    try:
        return runner.execute()
    except TaskCancelled:
        return runner.cancelled()
    except TaskError as exc:
        return runner.fail(exc)
    except Exception as exc:  # Defensive boundary for a web task process.
        error = TaskError(f"未处理的内部错误: {exc}", EXIT_INTERNAL, "INTERNAL")
        return runner.fail(error)
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        runner.close()


if __name__ == "__main__":
    raise SystemExit(main())
