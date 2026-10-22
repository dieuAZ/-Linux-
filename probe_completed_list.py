#!/usr/bin/env python3
"""Maintain the Linux-version -> completed-Probe driver list."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_PATH = ROOT / "config" / "probe_completed.json"


def load(path: Path = DEFAULT_PATH) -> dict[str, dict]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, dict] = {}
    for item in raw if isinstance(raw, list) else [raw]:
        if not isinstance(item, dict):
            continue
        for linux, value in item.items():
            if isinstance(value, dict):
                result[str(linux)] = {
                    "linux_path": str(value.get("linux_path", "")),
                    "drivers": [dict(driver) for driver in value.get("drivers", [])
                                if isinstance(driver, dict) and driver.get("name")],
                }
            elif isinstance(value, list):
                result[str(linux)] = {
                    "linux_path": "",
                    "drivers": [{"name": str(driver)} for driver in value],
                }
    return result


def save(catalog: dict[str, dict], path: Path = DEFAULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    value = []
    for linux, data in sorted(catalog.items()):
        drivers = sorted(data.get("drivers", []), key=lambda item: item.get("name", ""))
        value.append({linux: {"linux_path": data.get("linux_path", ""), "drivers": drivers}})
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def record_probe_completion(linux: str, driver: str, linux_path: str = "",
                            type_tags: list[str] | None = None,
                            vid: str = "", pid: str = "",
                            subvid: str = "", subpid: str = "",
                            path: Path = DEFAULT_PATH) -> None:
    catalog = load(path)
    entry = catalog.setdefault(linux, {"linux_path": linux_path, "drivers": []})
    if linux_path:
        entry["linux_path"] = linux_path
    drivers = entry.setdefault("drivers", [])
    value = next((item for item in drivers if item.get("name") == driver), None)
    if value is None:
        value = {"name": driver}
        drivers.append(value)
    value["type_tags"] = sorted(set(type_tags or value.get("type_tags", [])))
    value["vid"] = vid or value.get("vid", "")
    value["pid"] = pid or value.get("pid", "")
    if subvid:
        value["subvid"] = subvid
    if subpid:
        value["subpid"] = subpid
    save(catalog, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="维护已完成 Probe 的驱动清单")
    parser.add_argument("--record", nargs=2, metavar=("LINUX", "DRIVER"), help="记录一次成功 Probe")
    parser.add_argument("--linux-path", default="")
    parser.add_argument("--type-tag", action="append", default=[])
    parser.add_argument("--vid", default="")
    parser.add_argument("--pid", default="")
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH)
    args = parser.parse_args()
    if args.record:
        record_probe_completion(args.record[0], args.record[1], args.linux_path,
                                args.type_tag, args.vid, args.pid, path=args.path)
    print(json.dumps([{linux: value} for linux, value in load(args.path).items()],
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
