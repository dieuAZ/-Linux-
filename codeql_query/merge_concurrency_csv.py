#!/usr/bin/env python3
"""Merge unified concurrency CSV files and keep one row per semantic finding.

Only CSV files containing the unified ``concurrency_model`` column are read;
layer/debug CSV files are skipped automatically.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Mapping, Sequence


# These fields identify the analyzed event.  Proof-path metadata such as holder
# choice, call depth, or barrier spelling is intentionally not part of the key.
SEMANTIC_KEY_FIELDS: tuple[str, ...] = (
    "concurrency_model",
    "lifecycle_file",
    "lifecycle_line",
    "lifecycle_function",
    "lifecycle_api",
    "callback_entry",
    "free_file",
    "free_line",
    "free_function",
    "free_api",
    "freed_object_path",
    "use_file",
    "use_line",
    "use_function",
    "use_kind",
    "used_object_path",
    "path_relation",
)

DEPTH_FIELDS: tuple[str, ...] = (
    "lifecycle_to_callback_depth",
    "lifecycle_to_free_depth",
    "callback_call_depth",
    "free_call_depth",
)

# Preserve distinct safety evidence even after choosing one canonical proof.
AGGREGATE_FIELDS: tuple[str, ...] = (
    "protection_tag",
    "protection_detail",
    "barrier_context",
)


def normalize_model(value: str) -> str:
    value = value.strip().lower()
    aliases = {
        "irq": "irq",
        "hrtimer": "hrtimer",
        "kthread": "kthread",
        "napi": "napi",
        "rcu": "rcu",
        "tasklet": "tasklet",
        "timer": "timer",
        "workqueue": "workqueue",
        "work_queue": "workqueue",
    }
    return aliases.get(value, value or "unknown")


def normalize_key_value(field: str, value: str) -> str:
    value = (value or "").strip()
    if field.endswith("_file"):
        return value.replace("\\", "/").lower()
    if field.endswith("_line"):
        try:
            return str(int(value))
        except ValueError:
            return value
    if field == "concurrency_model":
        return normalize_model(value)
    return value


def semantic_key(row: Mapping[str, str]) -> tuple[str, ...]:
    """Return the stable semantic identity of one concurrency finding."""
    return tuple(
        normalize_key_value(field, row.get(field, ""))
        for field in SEMANTIC_KEY_FIELDS
    )


def semantic_id(key: Sequence[str]) -> str:
    raw = "\x1f".join(key).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


def parse_depth(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 1_000_000


def canonical_rank(row: Mapping[str, str], columns: Sequence[str]) -> tuple:
    depths = tuple(parse_depth(row.get(field, "")) for field in DEPTH_FIELDS)
    finite_depths = tuple(value for value in depths if value < 1_000_000)
    depth_sum = sum(finite_depths) if finite_depths else 1_000_000
    # Prefer the shortest proof, then the row with more populated evidence,
    # followed by a deterministic lexical tie-breaker.
    populated = sum(bool((row.get(column, "") or "").strip()) for column in columns)
    lexical = tuple(row.get(column, "") for column in columns)
    return (depth_sum, depths, -populated, lexical)


def discover_csvs(inputs: Iterable[str]) -> list[Path]:
    discovered: set[Path] = set()
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            discovered.update(item.resolve() for item in path.glob("*.csv"))
        elif any(char in raw for char in "*?["):
            parent = path.parent if str(path.parent) else Path.cwd()
            discovered.update(item.resolve() for item in parent.glob(path.name))
        elif path.is_file():
            discovered.add(path.resolve())
        else:
            raise FileNotFoundError(f"Input does not exist: {raw}")
    return sorted(discovered, key=lambda item: str(item).lower())


def read_unified_rows(paths: Sequence[Path]) -> tuple[list[str], list[dict[str, str]], list[Path]]:
    columns: list[str] = []
    rows: list[dict[str, str]] = []
    accepted: list[Path] = []

    for path in paths:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames or []
            if "concurrency_model" not in header:
                continue
            if not columns:
                columns = list(header)
            elif header != columns:
                raise ValueError(
                    f"Unified header mismatch in {path}: expected {len(columns)} columns, "
                    f"found {len(header)}"
                )
            accepted.append(path)
            for raw_row in reader:
                row = {column: raw_row.get(column, "") for column in columns}
                row["concurrency_model"] = normalize_model(row["concurrency_model"])
                row["source_csv"] = path.name
                rows.append(row)

    if not columns:
        raise ValueError("No unified concurrency CSV was found")
    return columns, rows, accepted


def merge_semantic_unique(
    columns: Sequence[str], rows: Sequence[dict[str, str]]
) -> list[dict[str, str]]:
    groups: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[semantic_key(row)].append(row)

    merged: list[dict[str, str]] = []
    for key, variants in groups.items():
        canonical = dict(min(variants, key=lambda row: canonical_rank(row, columns)))
        canonical["source_model"] = normalize_model(canonical.get("concurrency_model", ""))
        canonical["source_csv"] = " | ".join(
            sorted({row["source_csv"] for row in variants}, key=str.lower)
        )
        canonical["semantic_id"] = semantic_id(key)
        canonical["semantic_duplicate_count"] = str(len(variants))

        for field in AGGREGATE_FIELDS:
            values = sorted(
                {
                    (row.get(field, "") or "").strip()
                    for row in variants
                    if (row.get(field, "") or "").strip()
                },
                key=str.lower,
            )
            canonical[field] = " | ".join(values)
        merged.append(canonical)

    merged.sort(
        key=lambda row: (
            row["source_model"],
            semantic_key(row),
            row["semantic_id"],
        )
    )
    return merged


def write_csv(path: Path, columns: Sequence[str], rows: Sequence[Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    output_columns = [
        "source_model",
        *columns,
        "source_csv",
        "semantic_id",
        "semantic_duplicate_count",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Merge unified IRQ/hrtimer/kthread/NAPI/RCU/tasklet/timer/workqueue CSVs and remove semantic duplicates."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="CSV files, glob patterns, or directories containing unified CSV files",
    )
    parser.add_argument("-o", "--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        paths = discover_csvs(args.inputs)
        columns, rows, accepted = read_unified_rows(paths)
        unique_rows = merge_semantic_unique(columns, rows)
        write_csv(args.output.resolve(), columns, unique_rows)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"accepted_csv_files={len(accepted)}")
    print(f"input_rows={len(rows)}")
    print(f"semantic_unique_rows={len(unique_rows)}")
    print(f"removed_semantic_duplicates={len(rows) - len(unique_rows)}")
    print(f"output={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
