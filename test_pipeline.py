import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import PipelineService, RoundClock
from server import ClosingConnection


class Process:
    def __init__(self): self.done = False
    def poll(self): return 0 if self.done else None
    def wait(self, timeout=None):
        if not self.done: raise TimeoutError('still running')
        return 0


class Server:
    def __init__(self, root):
        self.ROOT = root
        self.PROBE_TARGETS = root / 'targets.json'
        self.LOCK = threading.RLock()
        self.PROCESSES = {}
        self.tasks = {}
        self.fail_kind = None
        self.key = True
        self.limit = 2
        (root / 'config').mkdir()
        (root / 'config' / 'test.config').write_text('{}')
    def db(self): return sqlite3.connect(self.ROOT / 'test.db', factory=ClosingConnection)
    def now(self): return '2026-10-11T00:00:00+00:00'
    def config(self): return {'pipeline': {'max_parallel': self.limit}}
    def llm_settings(self): return {'has_api_key': self.key}
    def read_catalog(self, path): return {'linux': ['one','two','three']}
    def fuzz_catalog(self): return {'linux':['one','two','three']}
    def list_tasks(self): return list(self.tasks.values())
    def get_task(self, key): return self.tasks.get(key)
    def task_dir(self, task): return self.ROOT / task['id']
    def create_task(self, payload, pipeline_id=None):
        task = dict(payload, id=str(len(self.tasks)+1), status='DRAFT')
        self.tasks[task['id']] = task
        self.task_dir(task).mkdir()
        return task
    def start_task(self, key, pipeline_id=None):
        task = self.tasks[key]
        task['status'] = 'FAILED' if task['task_type'] == self.fail_kind else 'COMPLETED'
        if task['task_type'] == 'FUZZ':
            task['status'] = 'RUNNING'
            self.PROCESSES[key] = Process()
    def stop_task(self, key):
        self.PROCESSES[key].done = True
        self.tasks[key]['status'] = 'CANCELLED'
        self.PROCESSES.pop(key)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.s = Server(Path(self.temp.name))
        self.p = PipelineService(self.s)
        self.p.initialize()
    def create(self, **options):
        with patch('pipeline.threading.Thread.start'):
            return self.p.create(dict(linux_version='linux', driver='one', auto_seed=False, **options))
    def test_validation(self):
        for payload in ({'driver':['one']}, {'max_duration_minutes':0}, {'auto_seed':'true'}):
            with self.assertRaises(ValueError):
                self.p.create(dict(linux_version='linux', driver='one', **{k:v for k,v in payload.items() if k!='driver'}) if 'driver' not in payload else dict(linux_version='linux', **payload))
        self.s.key=False
        with self.assertRaises(ValueError): self.create()
    def test_duplicate_and_other_target(self):
        self.create()
        with self.assertRaises(RuntimeError): self.create()
        with patch('pipeline.threading.Thread.start'):
            second=self.p.create(dict(linux_version='linux',driver='two'))
        self.assertEqual(second['status'],'QUEUED')
    def test_manual_target_conflict(self):
        self.create()
        with self.assertRaises(RuntimeError):
            self.p.check_task_creation(dict(linux_version='linux',driver='one',task_type='FUZZ'),None)
    def test_failed_stage_stops(self):
        self.s.fail_kind='STATIC_ANALYSIS'
        item=self.create()
        self.p.run(item['id'])
        self.assertEqual(self.p.get(item['id'])['status'],'FAILED')
        self.assertEqual([t['task_type'] for t in self.s.list_tasks()],['STATIC_ANALYSIS'])
    def test_success_without_seed(self):
        item=self.create()
        with patch('pipeline.RoundClock.update',return_value='time limit'):
            self.p.run(item['id'])
        self.assertEqual(self.p.get(item['id'])['status'],'COMPLETED')
        self.assertFalse(self.s.PROCESSES)
        self.assertEqual([t['task_type'] for t in self.s.list_tasks()],['STATIC_ANALYSIS','PROBE','FUZZ'])
    def test_seed_round_resets_and_cancel(self):
        with patch('pipeline.threading.Thread.start'):
            item=self.p.create(dict(linux_version='linux',driver='one',auto_seed=True))
        calls=[]
        def round_update(timer, coverage):
            calls.append(timer)
            if len(calls)==2: self.p.stop(item['id'])
            return 'time limit'
        with patch('pipeline.RoundClock.update',round_update):
            self.p.run(item['id'])
        self.assertEqual(self.p.get(item['id'])['status'],'CANCELLED')
        self.assertEqual(self.p.get(item['id'])['round'],2)
        self.assertIsNot(calls[0],calls[1])
        self.assertEqual([t['task_type'] for t in self.s.list_tasks()].count('SEED'),1)
        self.assertFalse(self.s.PROCESSES)
    def test_reuse_and_extra(self):
        previous=self.s.create_task(dict(linux_version='linux',driver='one',task_type='PROBE',extra_enabled=False))
        previous['status']='COMPLETED'
        item=self.create(extra_enabled=True)
        self.assertNotIn('PROBE',item['reused'])
        self.p.update(item['id'],status='CANCELLED')
        item=self.create()
        self.assertEqual(item['reused']['PROBE'],previous['id'])
    def test_seed_failure_stops_manager(self):
        self.s.fail_kind='SEED'
        with patch('pipeline.threading.Thread.start'):
            item=self.p.create(dict(linux_version='linux',driver='one',auto_seed=True))
        with patch('pipeline.RoundClock.update',return_value='limit'):
            self.p.run(item['id'])
        self.assertEqual(self.p.get(item['id'])['status'],'FAILED')
        self.assertEqual(self.p.get(item['id'])['round'],1)
        self.assertFalse(self.s.PROCESSES)
    def test_stop_failure_preserves_reservation(self):
        item=self.create()
        with patch('pipeline.RoundClock.update',return_value='limit'), patch.object(self.s,'stop_task',side_effect=RuntimeError('cannot stop')):
            self.p.run(item['id'])
        self.assertEqual(self.p.get(item['id'])['status'],'INTERRUPTED')
        self.assertIn(('linux','one'),self.p.reserved_targets())
    def test_cancel_queued(self):
        item=self.create()
        self.p.stop(item['id'])
        self.p.run(item['id'])
        self.assertEqual(self.p.get(item['id'])['status'],'CANCELLED')
        self.assertFalse(self.s.tasks)
    def test_restart_preserves_reservation(self):
        item=self.create()
        self.p.initialize()
        self.assertEqual(self.p.get(item['id'])['status'],'INTERRUPTED')
        with self.assertRaises(RuntimeError): self.create()
        self.assertIn(('linux','one'),self.p.reserved_targets())
    def test_coverage_reads_syzkaller_equals_status(self):
        task = self.s.create_task(dict(linux_version='linux', driver='one', task_type='FUZZ'))
        logs = self.s.task_dir(task) / 'logs'
        logs.mkdir()
        (logs / 'workflow.log').write_text('corpus=4 coverage=234 exec total=20\n')
        self.assertEqual(self.p.coverage(task), 234)
        (logs / 'workflow.log').write_text('corpus: 6 coverage: 345\n')
        self.assertEqual(self.p.coverage(task), 345)
    def test_concurrency_queue(self):
        self.s.limit=1
        first=self.create()
        self.p.update(first['id'],status='RUNNING')
        with patch('pipeline.threading.Thread.start'):
            second=self.p.create(dict(linux_version='linux',driver='two'))
        class Wait:
            def wait(inner, seconds):
                self.assertEqual(self.p.get(second['id'])['status'],'QUEUED')
                self.p.stop(second['id'])
        self.p.wakeup=Wait()
        self.p.run(second['id'])
        self.assertFalse(self.s.tasks)


class ClockTests(unittest.TestCase):
    def test_convergence_growth_missing_and_limit(self):
        ticks=[0]
        timer=RoundClock(180,30,10,clock=lambda:ticks[0])
        self.assertIsNone(timer.update(None))
        timer.update(100)
        ticks[0]=20
        self.assertIsNone(timer.update(110))
        ticks[0]=49
        self.assertIsNone(timer.update(110))
        ticks[0]=50
        self.assertEqual(timer.update(110),'覆盖率收敛')
        self.assertIsNone(timer.update(None))
        self.assertIsNone(timer.update(110))
        ticks[0]=180
        self.assertEqual(timer.update(None),'达到每轮最长时间')
    def test_new_round_has_fresh_clocks(self):
        timer=RoundClock(180,30,clock=lambda:1000)
        self.assertEqual(timer.started,1000)
        self.assertIsNone(timer.changed)
        self.assertIsNone(timer.update(100))


if __name__=='__main__': unittest.main()
