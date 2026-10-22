"""Persistent, single-target pipeline scheduler. No dependency on external packages."""
import json
import math
import threading
import time
import uuid

from fuzz_metrics import COVERAGE_RE, read_log_tail


ACTIVE = {'QUEUED', 'RUNNING', 'STOPPING', 'INTERRUPTED'}


class Cancelled(Exception):
    pass


class RoundClock:
    def __init__(self, maximum, window, threshold=10, clock=time.monotonic):
        self.clock = clock
        self.maximum, self.window, self.threshold = maximum, window, threshold
        self.started = clock()
        self.changed = None
        self.baseline = None

    def update(self, coverage):
        current = self.clock()
        if coverage is not None:
            if self.baseline is None or coverage < self.baseline or coverage >= self.baseline + self.threshold:
                self.baseline, self.changed = coverage, current
            elif self.changed is None:
                self.changed = current
        else:
            self.changed = None
        if current - self.started >= self.maximum:
            return '达到每轮最长时间'
        # Missing/stale telemetry is never evidence of convergence.
        if coverage is not None and self.changed is not None and current - self.changed >= self.window:
            return '覆盖率收敛'
        return None


class PipelineService:
    def __init__(self, server):
        self.s = server
        self.wakeup = threading.Event()
        self.log_samples = {}

    def initialize(self):
        with self.s.db() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS pipelines (id TEXT PRIMARY KEY, document TEXT NOT NULL)')
        # Never duplicate a possibly surviving QEMU/Docker process after restart.
        for item in self.list():
            if item['status'] in ACTIVE:
                self.update(item['id'], status='INTERRUPTED', error='服务已重启；请确认旧进程已停止后解除占用。')

    def list(self):
        with self.s.db() as conn:
            return [json.loads(row[0]) for row in conn.execute('SELECT document FROM pipelines ORDER BY rowid DESC')]

    def get(self, key):
        with self.s.db() as conn:
            row = conn.execute('SELECT document FROM pipelines WHERE id=?', (key,)).fetchone()
        if not row:
            raise KeyError('流水线不存在')
        return json.loads(row[0])

    def update(self, key, **fields):
        with self.s.LOCK:
            item = self.get(key)
            item.update(fields, updated_at=self.s.now())
            with self.s.db() as conn:
                conn.execute('UPDATE pipelines SET document=? WHERE id=?', (json.dumps(item, ensure_ascii=False), key))
            return item

    def reserved_targets(self):
        return {(p['linux_version'], p['driver']) for p in self.list() if p['status'] in ACTIVE}

    def check_task_creation(self, payload, owner):
        if payload.get('task_type') == 'CODEQL_QUERY':
            return
        parent = self.s.get_task(payload.get('parent_task_id', '')) if payload.get('parent_task_id') else None
        target = parent or payload
        for item in self.list():
            if item['status'] in ACTIVE and (item['linux_version'], item['driver']) == (target.get('linux_version'), target.get('driver')):
                if item['id'] != owner:
                    raise RuntimeError('该目标由一键启动管理，请在流水线页面操作或先停止流水线')

    def reusable(self, item, kind):
        if not item['reuse_results']:
            return None
        for task in self.s.list_tasks():
            if (task['linux_version'], task['driver'], task['task_type'], task['status']) != (item['linux_version'], item['driver'], kind, 'COMPLETED'):
                continue
            if kind == 'PROBE' and item['extra_enabled'] and not task['extra_enabled']:
                continue
            if task['id'] in self.s.PROCESSES:
                continue
            if kind == 'PROBE' and item['driver'] not in self.s.fuzz_catalog().get(item['linux_version'], []):
                continue
            if self.s.task_dir(task).exists():
                return task['id']
        return None

    def create(self, payload):
        with self.s.LOCK:
            linux, driver = payload.get('linux_version'), payload.get('driver')
            if not isinstance(linux, str) or not isinstance(driver, str) or driver not in self.s.available_driver_catalog().get(linux, []):
                raise ValueError('请选择一个有效的 Linux 版本和驱动')
            if (linux, driver) in self.reserved_targets():
                raise RuntimeError('该目标已有流水线')
            if any(t['linux_version'] == linux and t['driver'] == driver and t['task_type'] != 'CODEQL_QUERY' and t['status'] in {'DRAFT','STARTING','RUNNING','STOPPING','READY_FOR_FUZZ'} for t in self.s.list_tasks()):
                raise RuntimeError('该目标已有未结束的任务')
            options = {}
            for name, default in [('reuse_results', True), ('auto_seed', True), ('extra_enabled', False)]:
                value = payload.get(name, default)
                if not isinstance(value, bool):
                    raise ValueError(f'{name} 必须为布尔值')
                options[name] = value
            for name, default, upper in [('convergence_window_minutes',30,1440), ('max_duration_minutes',180,10080)]:
                value = payload.get(name, default)
                if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
                    raise ValueError(f'{name} 必须为 1–{upper} 的整数')
                options[name] = value
            item = dict(id=str(uuid.uuid4()), linux_version=linux, driver=driver, status='QUEUED', stage='QUEUED', round=0,
                        tasks=[], reused={}, error=None, created_at=self.s.now(), **options)
            for kind in ('STATIC_ANALYSIS', 'PROBE'):
                previous = self.reusable(item, kind)
                if previous:
                    item['reused'][kind] = previous
            if 'PROBE' not in item['reused'] and not self.s.llm_settings()['has_api_key']:
                raise ValueError('请先到系统配置页面完成 LLM 配置')
            if not (self.s.ROOT / 'config' / 'test.config').is_file():
                raise ValueError('缺少 config/test.config 模板')
            with self.s.db() as conn:
                conn.execute('INSERT INTO pipelines VALUES (?,?)', (item['id'], json.dumps(item, ensure_ascii=False)))
            threading.Thread(target=self.run, args=(item['id'],), daemon=True).start()
            return item

    def check_cancel(self, key):
        if self.get(key)['status'] != 'RUNNING':
            raise Cancelled()

    def spawn(self, key, kind, parent=None):
        with self.s.LOCK:
            self.check_cancel(key)
            item = self.get(key)
            payload = {**item, 'task_type': kind, 'parent_task_id': parent}
            task = self.s.create_task(payload, pipeline_id=key)
            self.update(key, tasks=item['tasks'] + [task['id']], current_task_id=task['id'], stage=kind)
            self.s.start_task(task['id'], pipeline_id=key)
            return task['id']

    def assert_running(self, task_id):
        task = self.s.get_task(task_id)
        if not task or task['status'] in {'FAILED','CANCELLED','STOPPING','COMPLETED'}:
            raise RuntimeError('Fuzz 已提前退出，请查看任务日志')

    def wait_task(self, key, task_id, fuzz_id=None):
        while True:
            self.check_cancel(key)
            if fuzz_id:
                self.assert_running(fuzz_id)
            task = self.s.get_task(task_id)
            if task['status'] in {'FAILED','CANCELLED'}:
                raise RuntimeError(task.get('error_summary') or f"{task['task_type']} 执行失败，请查看日志")
            # Reports may precede process exit; wait for the supervisor as well.
            if task['status'] == 'COMPLETED' and task_id not in self.s.PROCESSES:
                return
            self.wakeup.wait(1)

    def coverage(self, task):
        report = task.get('report') or {}
        path = self.s.task_dir(task) / 'snapshot' / 'report.json'
        if path.exists() and time.time() - path.stat().st_mtime < 60:
            for section in ('metrics', 'fuzz'):
                value = report.get(section, {}).get('coverage_pcs')
                if isinstance(value, (int,float)) and not isinstance(value,bool) and math.isfinite(value) and value >= 0:
                    return value
        path = self.s.task_dir(task) / 'logs' / 'workflow.log'
        if path.exists() and time.time() - path.stat().st_mtime < 60:
            data, offset = read_log_tail(path, 65536)
            matches = list(COVERAGE_RE.finditer(data))
            if matches:
                position = offset + matches[-1].start()
                previous = self.log_samples.get(task['id'])
                if not previous or previous[0] != position:
                    self.log_samples[task['id']] = (position, time.monotonic())
                if time.monotonic() - self.log_samples[task['id']][1] < 60:
                    return int(matches[-1].group(1))
        return None

    def cleanup(self, key):
        errors = []
        for task_id in reversed(self.get(key)['tasks']):
            if task_id in self.s.PROCESSES:
                try:
                    process = self.s.PROCESSES[task_id]
                    if process.poll() is None:
                        self.s.stop_task(task_id)
                    process.wait(timeout=30)
                except Exception as exc:
                    errors.append(str(exc))
        if errors:
            raise RuntimeError('停止进程失败，仍保留目标占用：' + '; '.join(errors))

    def stop(self, key):
        with self.s.LOCK:
            item = self.get(key)
            if item['status'] == 'INTERRUPTED':
                raise RuntimeError('进程状态未知，请先在服务器核对并清理旧进程，再解除占用')
            if item['status'] in {'QUEUED','RUNNING'}:
                return self.update(key, status='STOPPING')
            return item

    def release(self, key, confirmed):
        with self.s.LOCK:
            item = self.get(key)
            if item['status'] != 'INTERRUPTED' or confirmed is not True:
                raise ValueError('仅在确认旧进程已清理后才能解除中断流水线的占用')
            if any(t in self.s.PROCESSES for t in item['tasks']):
                raise RuntimeError('仍有受管理的进程，请先停止它们')
            with self.s.db() as conn:
                for task_id in item['tasks']:
                    conn.execute("UPDATE tasks SET status='CANCELLED', stage='INTERRUPTED', finished_at=? WHERE id=? AND status IN ('DRAFT','RUNNING','STARTING','STOPPING','READY_FOR_FUZZ')", (self.s.now(), task_id))
            return self.update(key, status='CANCELLED', finished_at=self.s.now())

    def run(self, key):
        try:
            while True:
                with self.s.LOCK:
                    item = self.get(key)
                    if item['status'] == 'STOPPING':
                        raise Cancelled()
                    limit = max(1, int(self.s.config().get('pipeline', {}).get('max_parallel', 2)))
                    active = sum(p['status'] in {'RUNNING','STOPPING','INTERRUPTED'} for p in self.list() if p['id'] != key)
                    queue = [p['id'] for p in reversed(self.list()) if p['status'] == 'QUEUED']
                    if active < limit and queue and queue[0] == key:
                        self.update(key, status='RUNNING', started_at=self.s.now())
                        break
                self.wakeup.wait(1)
            for kind in ('STATIC_ANALYSIS','PROBE'):
                self.check_cancel(key)
                item = self.get(key)
                if kind not in item['reused']:
                    self.wait_task(key, self.spawn(key, kind))
            fuzz_id = self.spawn(key, 'FUZZ')
            round_number = 0
            while True:
                round_number += 1
                item = self.get(key)
                timer = RoundClock(item['max_duration_minutes'] * 60, item['convergence_window_minutes'] * 60,
                                   max(1, int(self.s.config().get('fuzz_cycle', {}).get('min_new_coverage_pcs', 10))))
                self.update(key, stage='FUZZ', round=round_number, current_task_id=fuzz_id, round_started_at=self.s.now(), coverage_pcs=None, convergence_elapsed_seconds=0)
                while True:
                    self.check_cancel(key)
                    self.assert_running(fuzz_id)
                    coverage = self.coverage(self.s.get_task(fuzz_id))
                    reason = timer.update(coverage)
                    self.update(key, coverage_pcs=coverage, elapsed_seconds=int(time.monotonic()-timer.started),
                                convergence_elapsed_seconds=int(time.monotonic()-timer.changed) if timer.changed is not None else 0)
                    if reason:
                        break
                    self.wakeup.wait(2)
                self.update(key, round_end_reason=reason)
                if not item['auto_seed']:
                    self.cleanup(key)
                    self.update(key, status='COMPLETED', stage='FINISHED', finished_at=self.s.now())
                    return
                # Keep Manager alive: the seed generator needs its HTTP endpoint.
                self.wait_task(key, self.spawn(key, 'SEED', fuzz_id), fuzz_id=fuzz_id)
                # A new RoundClock resets both clocks. Same Manager/workdir preserve corpus.
        except Cancelled:
            final_status, error = 'CANCELLED', None
        except Exception as exc:
            final_status, error = 'FAILED', str(exc)
        try:
            self.cleanup(key)
        except Exception as exc:
            final_status, error = 'INTERRUPTED', str(exc)
        self.update(key, status=final_status, error=error, finished_at=self.s.now())
