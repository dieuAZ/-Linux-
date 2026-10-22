"""Read-only telemetry from a Syzkaller manager log and work directory."""

import json
import re
from datetime import datetime
from pathlib import Path


COVERAGE_RE = re.compile(rb'\bcover(?:age)?\s*[:=]\s*(\d+)\b')
CORPUS_RE = re.compile(rb'\bcorpus\s*[:=]\s*(\d+)\b')
EXEC_RE = re.compile(rb'\bexec\s+total\s*[:=]\s*(\d+)\b')
SPEED_RE = re.compile(rb'\((\d+)\s*/\s*sec\)')
STAMP_RE = re.compile(rb'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s')
CRASH_RE = re.compile(rb'\bVM\s+\d+:\s+crash:\s*([^\r\n]+)')


def read_log_tail(path: Path, limit: int = 100_000) -> tuple[bytes, int]:
    with path.open('rb') as log:
        log.seek(0, 2)
        offset = max(0, log.tell() - limit)
        log.seek(offset)
        return log.read(), offset


def parse_status(data: bytes) -> dict[str, int]:
    """Take the most recent manager status line, not a crash or build message."""
    for line in reversed(data.splitlines()):
        coverage = COVERAGE_RE.search(line)
        corpus = CORPUS_RE.search(line)
        if coverage and corpus:
            return {'coverage_pcs': int(coverage.group(1)), 'corpus_count': int(corpus.group(1))}
    return {}


def read_metrics(task_directory: Path) -> dict[str, int]:
    metrics = {}
    log_path = task_directory / 'logs' / 'workflow.log'
    try:
        metrics.update(parse_status(read_log_tail(log_path)[0]))
    except OSError:
        pass

    config_path = task_directory / 'snapshot' / 'configs' / 'fuzz.config'
    try:
        workdir = Path(json.loads(config_path.read_text(encoding='utf-8'))['workdir'])
        if workdir.is_dir():
            crashes = workdir / 'crashes'
            metrics['crash_count'] = sum(
                child.is_dir() and (child / 'description').is_file()
                for child in crashes.iterdir()
            ) if crashes.is_dir() else 0
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return metrics


def parse_telemetry(data: bytes, max_points: int = 720) -> dict:
    """Return real Syzkaller status samples; never interpolate missing observations."""
    points = []
    crashes = set()
    for line in data.splitlines():
        crash = CRASH_RE.search(line)
        if crash:
            crashes.add(crash.group(1).strip().decode('utf-8', errors='replace'))
        stamp = STAMP_RE.match(line)
        coverage = COVERAGE_RE.search(line)
        corpus = CORPUS_RE.search(line)
        executed = EXEC_RE.search(line)
        if not (stamp and coverage and corpus and executed):
            continue
        try:
            recorded = datetime.strptime(stamp.group(1).decode('ascii'), '%Y/%m/%d %H:%M:%S').astimezone().isoformat()
        except ValueError:
            continue
        speed = SPEED_RE.search(line)
        points.append({'at': recorded, 'coverage_pcs': int(coverage.group(1)),
                       'corpus_count': int(corpus.group(1)), 'executions': int(executed.group(1)),
                       'execs_per_sec': int(speed.group(1)) if speed else None})
    return {'samples': points[-max_points:], 'last': points[-1] if points else None,
            'crash_titles_in_log': len(crashes)}


def read_telemetry(task_directory: Path) -> dict:
    log_path = task_directory / 'logs' / 'workflow.log'
    log_available = False
    try:
        parsed = parse_telemetry(read_log_tail(log_path, 2_000_000)[0])
        log_available = True
    except OSError:
        parsed = {'samples': [], 'last': None, 'crash_titles_in_log': 0}
    metrics = read_metrics(task_directory)
    # Crash folders contain deduplicated reports. Log titles are a fallback
    # when the work directory is unavailable on this host.
    parsed['crash_count'] = metrics.get('crash_count', parsed['crash_titles_in_log'] if log_available else None)
    parsed['crash_source'] = 'workdir' if 'crash_count' in metrics else 'log'
    config_path = task_directory / 'snapshot' / 'configs' / 'fuzz.config'
    try:
        vm = json.loads(config_path.read_text(encoding='utf-8'))['vm']
        parsed['configured_vms'] = int(vm['count'])
    except (OSError, ValueError, KeyError, TypeError):
        parsed['configured_vms'] = None
    return parsed
