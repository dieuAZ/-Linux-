#!/usr/bin/env python3
"""Connect the existing ops screen to semantic deduplication and LLM triage."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def write_ops_semantic(source: Path, destination: Path) -> int:
    fields = (
        "semantic_id", "source_model", "concurrency_model", "lifecycle_file",
        "lifecycle_line", "lifecycle_function", "lifecycle_api", "lifecycle_kind",
        "callback_entry", "callback_file", "callback_function", "free_file",
        "free_line", "free_function", "free_api", "free_kind", "holder_root",
        "holder_root_kind", "holder_type", "callback_data_path", "freed_object_path",
        "use_file", "use_line", "use_function", "use_kind", "used_object_path",
        "path_relation", "protection_tag", "barrier_context", "ops_screen_verdict",
        "ops_screen_result",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with source.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        with destination.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in reader:
                free_path = row.get("freed_path") or row.get("freed_object_path", "")
                use_path = row.get("used_path") or row.get("used_object_path", "")
                lifecycle_file = row.get("table_file", "")
                lifecycle_line = row.get("ops_instance_line", "")
                table = row.get("ops_table", "")
                use_file = row.get("use_file", "")
                use_function = row.get("use_function", "")
                row_id_source = "\x1f".join((lifecycle_file, lifecycle_line, table,
                    row.get("free_file", ""), row.get("free_line", ""),
                    row.get("free_function", ""), use_file, row.get("use_line", ""), use_function))
                import hashlib
                semantic_id = hashlib.sha256(row_id_source.encode("utf-8")).hexdigest()[:20]
                writer.writerow({
                    **row,
                    "semantic_id": semantic_id,
                    "source_model": "ops",
                    "concurrency_model": "ops",
                    "lifecycle_file": lifecycle_file,
                    "lifecycle_line": lifecycle_line,
                    "lifecycle_function": table,
                    "lifecycle_api": "ops_dispatch",
                    "lifecycle_kind": "ops_dispatch",
                    "callback_entry": row.get("use_method", ""),
                    "callback_file": use_file,
                    "callback_function": use_function,
                    "free_kind": row.get("free_api", "") or "ops_free",
                    "holder_root": free_path,
                    "holder_root_kind": row.get("object_evidence_kind", "") or "ops_object",
                    "holder_type": row.get("runtime_object_key", "") or row.get("freed_type", "") or "ops_object",
                    "callback_data_path": use_path,
                    "freed_object_path": free_path,
                    "use_file": use_file,
                    "use_function": use_function,
                    "use_kind": "ops_method",
                    "used_object_path": use_path,
                })
                count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--dedup-script", type=Path, required=True)
    parser.add_argument("--triage-script", type=Path, required=True)
    parser.add_argument("--prompt-dir", type=Path, required=True)
    parser.add_argument("--csv-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--llm-settings", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--dedup-dir", type=Path, required=True)
    parser.add_argument("--auto-retry-errors", action="store_true")
    parser.add_argument("--max-error-retries", type=int, default=3)
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import codeql_llm_review as legacy_review
    from ops_concurrency_screen import screen_ops

    settings_path = args.llm_settings
    if not os.access(settings_path, os.R_OK):
        fallback = Path(__file__).resolve().parent / "llm-settings.json"
        if fallback.is_file():
            settings_path = fallback
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    api = settings.get("api") if isinstance(settings.get("api"), dict) else {}
    endpoint = str(api.get("url") or settings.get("api_base") or "")
    model = str(api.get("model") or settings.get("model") or "")
    api_key = str(api.get("key") or settings.get("api_key") or "")
    key_env = str(api.get("key_env") or "LLM_API_KEY")
    if not api_key and key_env in os.environ:
        api_key = os.environ[key_env]
    if not endpoint or not model or not api_key:
        parser.error("LLM endpoint/model/key missing in configured settings")

    ops_summary = screen_ops(legacy_review, args.csv_dir, args.source_root,
                             settings_path, args.output_dir)
    ops_usage = dict(legacy_review.LLM_USAGE_TOTAL)
    ops_summary_path = args.output_dir / "ops_concurrency_summary.json"
    ops_summary_data = json.loads(ops_summary_path.read_text(encoding="utf-8"))
    ops_summary_data["token_usage"] = ops_usage
    ops_summary_path.write_text(json.dumps(ops_summary_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ops_semantic = args.output_dir / "ops_semantic.csv"
    write_ops_semantic(Path(ops_summary["passed_csv"]), ops_semantic)

    dedup = subprocess.run(
        [sys.executable, str(args.dedup_script), str(args.input_root),
         "--output-dir", str(args.dedup_dir), "--extra-semantic-csv", str(ops_semantic)],
        check=False,
    )
    if dedup.returncode:
        return dedup.returncode

    env = os.environ.copy()
    env[key_env] = api_key
    triage_args = [sys.executable, str(args.triage_script),
        "--input-csv", str(args.dedup_dir / "all_models_semantic.csv"),
        "--source-root", str(args.source_root), "--output-dir", str(args.output_dir),
        "--prompt-dir", str(args.prompt_dir), "--endpoint", endpoint, "--model", model,
        "--api-key-env", key_env, "--timeout", "300", "--max-output-tokens", "8192",
        "--interval-seconds", "3"]
    max_retries = min(3, max(0, args.max_error_retries)) if args.auto_retry_errors else 0
    for retry in range(max_retries + 1):
        retry_args = triage_args + (["--retry-errors"] if retry else [])
        triage = subprocess.run(retry_args, env=env, check=False)
        if triage.returncode not in (0, 2):
            return triage.returncode
        summary_path = args.output_dir / "triage_summary.json"
        if not summary_path.is_file():
            return triage.returncode
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        remaining = int(summary.get("status_counts", {}).get("error", 0))
        if not remaining or retry >= max_retries:
            break
        print(f"Retrying {remaining} errored LLM unit(s), attempt {retry + 1}/{max_retries}", flush=True)
    summary["total_input_tokens"] = int(summary.get("total_input_tokens", 0)) + ops_usage["input_tokens"]
    summary["total_output_tokens"] = int(summary.get("total_output_tokens", 0)) + ops_usage["output_tokens"]
    summary["total_tokens"] = int(summary.get("total_tokens", 0)) + ops_usage["total_tokens"]
    summary["ops_token_usage"] = ops_usage
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
