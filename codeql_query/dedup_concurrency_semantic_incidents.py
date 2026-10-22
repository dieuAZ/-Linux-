#!/usr/bin/env python3
"""Collapse CodeQL concurrency evidence rows into semantic incidents.

Inputs are never modified. One representative row is retained for every
semantic incident and the remaining use-site rows are summarized as evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Mapping, Sequence


SEMANTIC_KEY_FIELDS = (
    "concurrency_model",
    "lifecycle_file",
    "lifecycle_line",
    "lifecycle_function",
    "lifecycle_api",
    "lifecycle_kind",
    "callback_entry",
    "free_file",
    "free_line",
    "free_function",
    "free_api",
    "free_kind",
    "holder_root",
    "holder_root_kind",
    "holder_type",
    "callback_data_path",
    "freed_object_path",
)

METADATA_FIELDS = (
    "semantic_id",
    "source_model",
    "semantic_evidence_count",
    "semantic_use_function_count",
    "semantic_use_site_count",
    "semantic_used_path_count",
    "semantic_source_driver_count",
    "semantic_source_drivers",
    "semantic_use_functions",
    "semantic_use_files",
    "semantic_use_kinds",
    "semantic_protection_tags",
    "semantic_barrier_contexts",
    "semantic_allocation_boundary_contexts",
    "representative_source_driver",
    "representative_source_csv",
)


def compact(value: str) -> str:
    return " ".join((value or "").split())


def normalized(field: str, value: str) -> str:
    value = compact(value)
    if field.endswith("_file"):
        return value.replace("\\", "/").lower()
    if field.endswith("_line"):
        try:
            return str(int(value))
        except ValueError:
            return value
    if field in {"holder_root", "callback_data_path", "freed_object_path"}:
        return re.sub(r"\s*(->|\.|\[|\])\s*", r"\1", value)
    return value


def incident_key(row: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(normalized(field, row.get(field, "")) for field in SEMANTIC_KEY_FIELDS)


def incident_id(key: Sequence[str]) -> str:
    return hashlib.sha256("\x1f".join(key).encode("utf-8")).hexdigest()[:20]


def integer(value: str, fallback: int = 1_000_000) -> int:
    try:
        return int((value or "").strip())
    except ValueError:
        return fallback


def representative_rank(row: Mapping[str, str]) -> tuple[object, ...]:
    use_file = normalized("use_file", row.get("use_file", ""))
    use_function = compact(row.get("use_function", ""))
    callback_entry = compact(row.get("callback_entry", ""))
    if use_file.startswith("drivers/"):
        file_rank = 0
    elif use_file.startswith(("kernel/", "mm/", "fs/", "net/")):
        file_rank = 1
    elif use_file.startswith("include/") or "/include/" in f"/{use_file}":
        file_rank = 3
    else:
        file_rank = 2
    kind_rank = {
        "field_access": 0,
        "deref_access": 1,
        "array_access": 2,
        "memory_api_access": 3,
    }.get(compact(row.get("use_kind", "")), 4)
    depth = sum(
        integer(row.get(field, ""), 1000)
        for field in (
            "lifecycle_to_callback_depth",
            "lifecycle_to_free_depth",
            "callback_call_depth",
            "free_call_depth",
        )
    )
    return (
        file_rank,
        0 if use_function == callback_entry else 1,
        kind_rank,
        depth,
        len(compact(row.get("used_object_path", ""))),
        use_file,
        integer(row.get("use_line", "")),
        use_function,
        compact(row.get("use_expression", "")),
    )


def joined(values: Iterable[str]) -> str:
    return " | ".join(sorted({compact(v) for v in values if compact(v)}, key=str.lower))


def discover(root: Path, output_dir: Path) -> list[Path]:
    output_dir = output_dir.resolve()
    result = []
    for path in root.rglob("*.csv"):
        resolved = path.resolve()
        if output_dir == resolved.parent or output_dir in resolved.parents:
            continue
        result.append(resolved)
    return sorted(result, key=lambda item: str(item).lower())


def read_inputs(paths: Sequence[Path], root: Path) -> tuple[list[str], list[dict[str, str]]]:
    columns: list[str] = []
    rows: list[dict[str, str]] = []
    required = set(SEMANTIC_KEY_FIELDS)
    for path in paths:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames or []
            missing = sorted(required.difference(header))
            if missing:
                raise ValueError(f"{path}: missing required columns: {', '.join(missing)}")
            for field in header:
                if field not in columns:
                    columns.append(field)
            try:
                relative = path.relative_to(root)
                directory_model = relative.parts[0].lower()
                driver = relative.parts[-2]
            except (ValueError, IndexError):
                directory_model = ""
                driver = path.parent.name
            for source in reader:
                row = {key: value or "" for key, value in source.items() if key is not None}
                model = compact(row.get("concurrency_model", "")).lower() or directory_model
                if not model:
                    continue
                row["concurrency_model"] = model
                row["_source_model"] = model
                row["_source_driver"] = driver
                row["_source_csv"] = str(path)
                rows.append(row)
    return columns, rows


def read_extra_semantic(
    paths: Sequence[Path], columns: list[str]
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Read already-deduplicated model outputs without changing their counts."""
    rows: list[dict[str, str]] = []
    evidence_by_model: dict[str, int] = defaultdict(int)
    metadata = set(METADATA_FIELDS)
    for path in paths:
        with path.expanduser().resolve().open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames or []
            missing = sorted(set(SEMANTIC_KEY_FIELDS).difference(header))
            if missing:
                raise ValueError(f"{path}: missing required columns: {', '.join(missing)}")
            for field in header:
                if field not in metadata and field not in columns:
                    columns.append(field)
            for source in reader:
                row = {key: value or "" for key, value in source.items() if key is not None}
                model = compact(row.get("source_model", "") or row.get("concurrency_model", "")).lower()
                if not model:
                    raise ValueError(f"{path}: semantic row has no concurrency model")
                row["source_model"] = model
                row["concurrency_model"] = model
                if not compact(row.get("semantic_id", "")):
                    row["semantic_id"] = incident_id(incident_key(row))
                try:
                    evidence_by_model[model] += int(row.get("semantic_evidence_count", "1") or "1")
                except ValueError as exc:
                    raise ValueError(f"{path}: invalid semantic_evidence_count") from exc
                rows.append(row)
    return rows, evidence_by_model


def merge(rows: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    groups: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[incident_key(row)].append(row)
    merged = []
    for key, evidence in groups.items():
        representative = dict(min(evidence, key=representative_rank))
        use_sites = {
            (
                normalized("use_file", row.get("use_file", "")),
                normalized("use_line", row.get("use_line", "")),
                compact(row.get("use_function", "")),
                compact(row.get("use_kind", "")),
                compact(row.get("used_object_path", "")),
            )
            for row in evidence
        }
        used_paths = {compact(row.get("used_object_path", "")) for row in evidence if compact(row.get("used_object_path", ""))}
        source_drivers = {compact(row.get("_source_driver", "")) for row in evidence if compact(row.get("_source_driver", ""))}
        representative.update(
            semantic_id=incident_id(key),
            source_model=representative.get("_source_model", ""),
            semantic_evidence_count=str(len(evidence)),
            semantic_use_function_count=str(len({compact(row.get("use_function", "")) for row in evidence})),
            semantic_use_site_count=str(len(use_sites)),
            semantic_used_path_count=str(len(used_paths)),
            semantic_source_driver_count=str(len(source_drivers)),
            semantic_source_drivers=joined(source_drivers),
            semantic_use_functions=joined(row.get("use_function", "") for row in evidence),
            semantic_use_files=joined(row.get("use_file", "") for row in evidence),
            semantic_use_kinds=joined(row.get("use_kind", "") for row in evidence),
            semantic_protection_tags=joined(row.get("protection_tag", "") for row in evidence),
            semantic_barrier_contexts=joined(row.get("barrier_context", "") for row in evidence),
            semantic_allocation_boundary_contexts=joined(row.get("allocation_boundary_context", "") for row in evidence),
            representative_source_driver=representative.get("_source_driver", ""),
            representative_source_csv=representative.get("_source_csv", ""),
        )
        merged.append(representative)
    return sorted(merged, key=lambda row: (incident_key(row), row["semantic_id"]))


def write_csv(path: Path, columns: Sequence[str], rows: Sequence[Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    output_columns = [*METADATA_FIELDS, *columns]
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=output_columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
        os.chmod(path, 0o664)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Semantically deduplicate unified concurrency-query CSV files without modifying inputs.")
    parser.add_argument("input_root", type=Path, help="Root containing model/driver/*.csv")
    parser.add_argument("--output-dir", required=True, type=Path, help="Separate output directory")
    parser.add_argument(
        "--extra-semantic-csv",
        action="append",
        default=[],
        type=Path,
        help="Already-deduplicated CSV to include in the unified output (repeatable)",
    )
    args = parser.parse_args()
    root = args.input_root.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"input root is not a directory: {root}")
    if root == output_dir:
        parser.error("output directory must differ from input root")
    paths = discover(root, output_dir)
    if not paths:
        parser.error("no input CSV files found")
    columns, rows = read_inputs(paths, root)
    incidents = merge(rows)
    extra_incidents, extra_evidence = read_extra_semantic(args.extra_semantic_csv, columns)
    known_ids = {row["semantic_id"] for row in incidents}
    duplicate_ids = sorted(
        {row["semantic_id"] for row in extra_incidents if row["semantic_id"] in known_ids}
    )
    if duplicate_ids:
        parser.error(f"extra semantic CSV duplicates {len(duplicate_ids)} existing semantic IDs")
    incidents.extend(extra_incidents)
    incidents.sort(key=lambda row: (incident_key(row), row["semantic_id"]))
    by_model_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_model_input: dict[str, int] = defaultdict(int)
    for row in rows:
        by_model_input[row["_source_model"]] += 1
    for model, count in extra_evidence.items():
        by_model_input[model] += count
    for row in incidents:
        by_model_rows[row["source_model"]].append(row)
    models = sorted({path.relative_to(root).parts[0].lower() for path in paths} | set(by_model_input))
    for model in models:
        write_csv(output_dir / f"{model}_semantic.csv", columns, by_model_rows.get(model, []))
    write_csv(output_dir / "all_models_semantic.csv", columns, incidents)
    stats = {
        "input_root": str(root),
        "output_dir": str(output_dir),
        "input_files": len(paths),
        "raw_input_rows": len(rows),
        "extra_semantic_files": len(args.extra_semantic_csv),
        "total_evidence_rows": sum(by_model_input.values()),
        "semantic_incidents": len(incidents),
        "collapsed_evidence_rows": sum(by_model_input.values()) - len(incidents),
        "models": {
            model: {
                "input_rows": by_model_input.get(model, 0),
                "semantic_incidents": len(by_model_rows.get(model, [])),
                "collapsed_evidence_rows": by_model_input.get(model, 0) - len(by_model_rows.get(model, [])),
            }
            for model in models
        },
    }
    (output_dir / "semantic_dedup_stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
