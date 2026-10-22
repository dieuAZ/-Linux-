#!/usr/bin/env python3
"""Assemble static call-graph evidence for the ops concurrency screen.

Reads the three CodeQL evidence CSVs produced by the runner:

  - ops_function_ranges.csv  (file, qualified_name, name, start_line, end_line,
                              start_column, end_column)
  - ops_direct_calls.csv     (caller_name, caller_file, caller_start_line,
                              callee_name, callee_short_name, callee_file,
                              callee_start_line, call_file, call_line, call_column)
  - ops_indirect_calls.csv   (enclosing_function, enclosing_file, enclosing_start_line,
                              call_file, call_line, call_column, call_expression,
                              callee_type, method_name, receiver_expression)

The module builds a location-keyed function index (file + start position) and a
direct call graph, then assembles per-candidate evidence. Call relationships are
taken ONLY from the exported edges; anything not present in the edges is recorded
as unresolved/unknown instead of being guessed from source text or name similarity.

Function bodies are emitted exactly once, in ``functions``, keyed by a stable
``ref`` of ``"<file>:<start_line>"``. The relationship sections reference that
store by ``ref`` (or by name when the function has no in-database definition), so
a function shared by the free and use callbacks, or a dispatch function with
several call sites, contributes its body only once.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable

# Bounds that keep the prompt inside the model context window while preserving
# full function sources (the whole point of the static-evidence approach).
MAX_HELPERS = 8        # direct callees of the free/use function whose source is included
MAX_CALLERS = 8        # direct callers of the free/use function whose source is included
MAX_DISPATCH = 16      # dispatch sites whose enclosing function source is included
MAX_CHAIN_DEPTH = 3    # transitive caller-chain depth
MAX_CHAIN_NODES = 16   # cap on total nodes in an upper chain

EVIDENCE_CSVS = {
    "functions": "ops_function_ranges.csv",
    "direct": "ops_direct_calls.csv",
    "indirect": "ops_indirect_calls.csv",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _loc_key(file: str, line: int | None) -> tuple[str, int] | None:
    if not file or line is None or line <= 0:
        return None
    return (_norm(file), line)


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [{k: _text(v) for k, v in row.items()} for row in csv.DictReader(handle)]


class FunctionIndex:
    """Location-keyed index over the exported function ranges."""

    def __init__(self, rows: Iterable[dict[str, str]]) -> None:
        self.by_loc: dict[tuple[str, int], dict[str, Any]] = {}
        self.by_name: dict[str, list[dict[str, Any]]] = {}
        self.by_qname: dict[str, list[dict[str, Any]]] = {}
        self.by_file: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            file = _norm(row.get("file", ""))
            start = _int(row.get("start_line"))
            if not file or start is None:
                continue
            rec = {
                "file": file,
                "qualified_name": row.get("qualified_name", ""),
                "name": row.get("name", ""),
                "start_line": start,
                "end_line": _int(row.get("end_line")) or start,
                "start_column": _int(row.get("start_column")) or 0,
                "end_column": _int(row.get("end_column")) or 0,
            }
            # First record wins so duplicate declaration/definition rows collapse.
            self.by_loc.setdefault((file, start), rec)
            self.by_name.setdefault(rec["name"], []).append(rec)
            self.by_file.setdefault(file, []).append(rec)
            if rec["qualified_name"]:
                self.by_qname.setdefault(rec["qualified_name"], []).append(rec)

    def get(self, file: str, start_line: int | None) -> dict[str, Any] | None:
        key = _loc_key(file, start_line)
        return self.by_loc.get(key) if key else None

    def enclosing(self, file: str, line: int | None) -> dict[str, Any] | None:
        """Return the function whose [start_line, end_line] range contains (file, line)."""
        if not file or line is None:
            return None
        file = _norm(file)
        for rec in self.by_file.get(file, []):
            if rec["start_line"] <= line <= rec["end_line"]:
                return rec
        return None

    def resolve(self, name: str, hint_file: str = "", hint_line: int | None = None) -> dict[str, Any] | None:
        """Resolve a short name to a unique record, or None when ambiguous/absent."""
        candidates = self.by_name.get(name, [])
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        hint_file = _norm(hint_file)
        if hint_file and hint_line is not None:
            containing = [c for c in candidates
                          if c["file"] == hint_file and c["start_line"] <= hint_line <= c["end_line"]]
            if len(containing) == 1:
                return containing[0]
        if hint_file:
            same_file = [c for c in candidates if c["file"] == hint_file]
            if len(same_file) == 1:
                return same_file[0]
        return None

    def all_named(self, name: str) -> list[dict[str, Any]]:
        return self.by_name.get(name, [])


class CallGraph:
    """Direct call graph over the exported resolved call edges."""

    def __init__(self, edges: Iterable[dict[str, str]], index: FunctionIndex) -> None:
        self.index = index
        self.callees_of: dict[tuple[str, int], list[dict[str, Any]]] = {}
        self.callers_of: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for raw in edges:
            edge = dict(raw)
            edge["caller_key"] = _loc_key(raw.get("caller_file"), _int(raw.get("caller_start_line")))
            edge["callee_key"] = _loc_key(raw.get("callee_file"), _int(raw.get("callee_start_line")))
            if edge["caller_key"]:
                self.callees_of.setdefault(edge["caller_key"], []).append(edge)
            if edge["callee_key"]:
                self.callers_of.setdefault(edge["callee_key"], []).append(edge)


class StaticEvidence:
    """Loaded bundle of the three evidence CSVs, shared across candidates."""

    def __init__(self, csv_dir: Path) -> None:
        self.csv_dir = Path(csv_dir)
        self.index = FunctionIndex(_read_csv(self.csv_dir / EVIDENCE_CSVS["functions"]))
        self.graph = CallGraph(_read_csv(self.csv_dir / EVIDENCE_CSVS["direct"]), self.index)
        self.indirect = _read_csv(self.csv_dir / EVIDENCE_CSVS["indirect"])
        self.available = bool(self.index.by_loc)


def load_function_index(csv_dir: Path) -> FunctionIndex:
    """Build a FunctionIndex from the exported function-ranges CSV (a global export)."""
    return FunctionIndex(_read_csv(Path(csv_dir) / EVIDENCE_CSVS["functions"]))


def extract_source(source_root: Path, file: str, start_line: int, end_line: int) -> str | None:
    """Read full numbered source lines for one function range, or None."""
    if not file or not start_line or not end_line or start_line > end_line:
        return None
    root = Path(source_root).resolve()
    path = (root / file).resolve()
    try:
        path.relative_to(root)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    if start_line < 1 or end_line > len(lines):
        return None
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(start_line, end_line + 1))


def _function_source(rec: dict[str, Any] | None, source_root: Path) -> str | None:
    if not rec:
        return None
    return extract_source(source_root, rec["file"], rec["start_line"], rec["end_line"])


def _ref_of(rec: dict[str, Any]) -> str:
    return f"{rec['file']}:{rec['start_line']}"


class _FunctionStore:
    """Dedup'd store: each distinct function (file + start line) appears once."""

    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self.items: list[dict[str, Any]] = []
        self.by_key: dict[tuple[str, int], int] = {}

    def ref(self, rec: dict[str, Any] | None) -> str | None:
        if rec is None:
            return None
        key = (rec["file"], rec["start_line"])
        idx = self.by_key.get(key)
        if idx is None:
            idx = len(self.items)
            self.by_key[key] = idx
            self.items.append({
                "ref": _ref_of(rec),
                "name": rec["name"],
                "qualified_name": rec["qualified_name"],
                "file": rec["file"],
                "start_line": rec["start_line"],
                "end_line": rec["end_line"],
                "source": _function_source(rec, self.source_root),
            })
        return self.items[idx]["ref"]


def _upper_chain(graph: CallGraph, start_key: tuple[str, int] | None) -> list[dict[str, Any]]:
    """Breadth-first transitive callers of a function, bounded by depth and size."""
    if start_key is None:
        return []
    seen: set[tuple[str, int]] = {start_key}
    nodes: list[dict[str, Any]] = []
    frontier = [start_key]
    for _ in range(MAX_CHAIN_DEPTH):
        nxt: list[tuple[str, int]] = []
        for key in frontier:
            for edge in graph.callers_of.get(key, []):
                caller_key = edge["caller_key"]
                if not caller_key or caller_key in seen:
                    continue
                seen.add(caller_key)
                nodes.append({"caller_name": edge["caller_name"],
                              "caller_file": edge["caller_file"],
                              "caller_start_line": edge["caller_start_line"],
                              "calls_at_file": edge["call_file"],
                              "calls_at_line": _int(edge["call_line"])})
                nxt.append(caller_key)
                if len(nodes) >= MAX_CHAIN_NODES:
                    return nodes
        frontier = nxt
        if not frontier:
            break
    return nodes


def assemble(candidate: dict[str, Any], source_root: Path, evidence: StaticEvidence) -> dict[str, Any]:
    """Assemble the static evidence for one ops candidate, with dedup'd function sources."""
    source_root = Path(source_root)
    c = {k: _text(v) for k, v in candidate.items()}
    index = evidence.index
    graph = evidence.graph
    store = _FunctionStore(source_root)
    notes: list[str] = []

    free_fn_name = c.get("free_function", "")
    use_fn_name = c.get("use_function", "")
    free_method = c.get("free_method", "")
    use_method = c.get("use_method", "")
    free_file = c.get("free_file", "")
    use_file = c.get("use_file", "")
    free_line = _int(c.get("free_line"))
    use_line = _int(c.get("use_line"))
    table_file = c.get("table_file", "")
    ops_table = c.get("ops_table", "")
    interface_type = c.get("interface_type", "")

    def resolve_fn(name: str, hint_file: str, hint_line: int | None) -> dict[str, Any] | None:
        resolved = index.resolve(name, hint_file, hint_line)
        if resolved is None:
            named = index.all_named(name)
            if len(named) > 1:
                notes.append(f"函数名 '{name}' 在数据库中对应 {len(named)} 个定义，"
                             f"无法仅凭候选字段唯一区分，未猜测："
                             f"{[(r['file'], r['start_line']) for r in named]}")
            elif not named:
                notes.append(f"函数 '{name}' 在数据库中无定义（可能在外部/头文件中），无法提取源码。")
        return resolved

    free_fn = resolve_fn(free_fn_name, free_file, free_line)
    use_fn = resolve_fn(use_fn_name, use_file, use_line)
    free_key = (free_fn["file"], free_fn["start_line"]) if free_fn else None
    use_key = (use_fn["file"], use_fn["start_line"]) if use_fn else None

    # ---- Section 1: ops table binding (references the dedup'd function store) ----
    ops_binding = {
        "table": ops_table,
        "table_file": table_file,
        "interface_type": interface_type,
        "free": {"method": free_method, "function": free_fn_name,
                 "ref": store.ref(free_fn)},
        "use": {"method": use_method, "function": use_fn_name,
                "ref": store.ref(use_fn)},
    }

    def callee_entries(rec: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Direct callees (helpers) of one callback, referencing the dedup'd store."""
        entries: list[dict[str, Any]] = []
        if rec is None:
            return entries
        for edge in graph.callees_of.get((rec["file"], rec["start_line"]), [])[:MAX_HELPERS]:
            callee_rec = index.get(edge.get("callee_file", ""), _int(edge.get("callee_start_line")))
            item = {"called_at_file": edge["call_file"], "called_at_line": _int(edge["call_line"])}
            if callee_rec is not None:
                item["ref"] = store.ref(callee_rec)
                item["name"] = callee_rec["name"]
            else:
                item["name"] = edge.get("callee_short_name", "")
                item["qualified_name"] = edge.get("callee_name", "")
                item["note"] = "被调用方无数据库内定义（外部函数），未提供源码"
            entries.append(item)
        return entries

    def caller_entries(rec: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Direct callers of one callback, referencing the dedup'd store."""
        entries: list[dict[str, Any]] = []
        if rec is None:
            return entries
        for edge in graph.callers_of.get((rec["file"], rec["start_line"]), [])[:MAX_CALLERS]:
            caller_rec = index.get(edge.get("caller_file", ""), _int(edge.get("caller_start_line")))
            item = {"calls_at_file": edge["call_file"], "calls_at_line": _int(edge["call_line"])}
            if caller_rec is not None:
                item["ref"] = store.ref(caller_rec)
                item["name"] = caller_rec["name"]
            else:
                item["name"] = edge["caller_name"]
            entries.append(item)
        return entries

    # ---- Section 2: call relationships (callers + helpers + upper chains) ----
    call_relationships = {
        "helpers_of_free": callee_entries(free_fn),
        "helpers_of_use": callee_entries(use_fn),
        "direct_callers_of_free": caller_entries(free_fn),
        "direct_callers_of_use": caller_entries(use_fn),
        "upper_chain_of_free": _upper_chain(graph, free_key),
        "upper_chain_of_use": _upper_chain(graph, use_key),
    }

    # ---- Section 3: framework execution path (dispatch sites + unresolved) ----
    dispatch_free: list[dict[str, Any]] = []
    dispatch_use: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for site in evidence.indirect:
        method = site.get("method_name", "")
        enclosing_file = site.get("enclosing_file", "")
        enclosing_start = _int(site.get("enclosing_start_line"))
        enclosing_rec = index.get(enclosing_file, enclosing_start)
        item = {
            "enclosing_function": site.get("enclosing_function", ""),
            "call_file": site.get("call_file", ""),
            "call_line": _int(site.get("call_line")),
            "method_name": method,
            "receiver_expression": site.get("receiver_expression", ""),
            "callee_type": site.get("callee_type", ""),
        }
        if method == free_method and len(dispatch_free) < MAX_DISPATCH:
            if enclosing_rec is not None:
                item["enclosing_ref"] = store.ref(enclosing_rec)
            dispatch_free.append(item)
        elif method == use_method and len(dispatch_use) < MAX_DISPATCH:
            if enclosing_rec is not None:
                item["enclosing_ref"] = store.ref(enclosing_rec)
            dispatch_use.append(item)
        elif _loc_key(enclosing_file, enclosing_start) in (free_key, use_key):
            # An indirect call made inside the free/use callback itself: target unresolved.
            # Its enclosing function is already registered as the free/use function.
            unresolved.append(item)

    framework_path = {
        "dispatch_sites_of_free_method": dispatch_free,
        "dispatch_sites_of_use_method": dispatch_use,
        "unresolved_indirect_calls_in_callbacks": unresolved,
        "note": ("间接调用（函数指针调用）的目标在静态上未解析。dispatch_sites_* 仅按方法名匹配，"
                 "未做接收者（具体 ops 表）解析，可能包含其他表的同名方法分派点；"
                 "具体分派到哪个函数需结合 ops_binding 绑定证据判断，未做任何文本猜测。"),
    }

    return {
        "available": evidence.available,
        "ops_binding": ops_binding,
        # Dedup'd function bodies: one entry per (file, start_line).
        "functions": store.items,
        "call_relationships": call_relationships,
        "framework_path": framework_path,
        "notes": notes,
    }
