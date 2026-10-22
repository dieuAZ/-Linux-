import json
import tempfile
import unittest
from pathlib import Path

from fuzz_metrics import parse_status, parse_telemetry, read_metrics, read_telemetry


class FuzzMetricsTests(unittest.TestCase):
    def test_telemetry_uses_real_status_lines_and_unique_crashes(self):
        data=(b'2026/10/13 07:17:40 corpus=174 coverage=7910 exec total=8255 (16/sec)\n'
              b'2026/10/13 07:17:43 VM 1: crash: KCSAN: data-race in release_task\n'
              b'2026/10/13 07:17:48 VM 2: crash: KCSAN: data-race in release_task\n'
              b'2026/10/13 07:18:10 corpus=175 coverage=7912 exec total=8632 (15/sec)\n')
        telemetry=parse_telemetry(data)
        self.assertEqual(telemetry['last']['executions'],8632)
        self.assertEqual(telemetry['last']['corpus_count'],175)
        self.assertEqual(telemetry['last']['coverage_pcs'],7912)
        self.assertEqual(telemetry['last']['execs_per_sec'],15)
        self.assertEqual(telemetry['crash_titles_in_log'],1)
        self.assertEqual(len(telemetry['samples']),2)

    def test_no_log_does_not_invent_zero_crashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=read_telemetry(Path(temporary))
            self.assertIsNone(result['last'])
            self.assertEqual(result['samples'],[])
            self.assertIsNone(result['crash_count'])

    def test_parse_latest_syzkaller_status(self):
        log = (b'corpus=12 coverage=100 exec total=10\n'
               b'VM 1: crash: a bug\n'
               b'corpus=15 coverage=123 exec total=20\n')
        self.assertEqual(parse_status(log), {'corpus_count': 15, 'coverage_pcs': 123})
        self.assertEqual(parse_status(b'corpus: 2 coverage: 7\n'),
                         {'corpus_count': 2, 'coverage_pcs': 7})
        self.assertEqual(parse_status(b'no status\n'), {})

    def test_read_metrics_counts_distinct_crash_buckets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = root / 'task'
            (task / 'logs').mkdir(parents=True)
            (task / 'snapshot' / 'configs').mkdir(parents=True)
            (task / 'logs' / 'workflow.log').write_text(
                'corpus=5 coverage=9\nVM 1: crash: bug\nVM 2: crash: bug\n')
            workdir = root / 'manager'
            (workdir / 'crashes' / 'a').mkdir(parents=True)
            (workdir / 'crashes' / 'a' / 'description').write_text('bug')
            (workdir / 'crashes' / 'b').mkdir()
            (task / 'snapshot' / 'configs' / 'fuzz.config').write_text(
                json.dumps({'workdir': str(workdir)}))
            self.assertEqual(read_metrics(task),
                             {'corpus_count': 5, 'coverage_pcs': 9, 'crash_count': 1})
            (workdir / 'crashes' / 'b' / 'description').write_text('bug 2')
            self.assertEqual(read_metrics(task)['crash_count'], 2)


if __name__ == '__main__':
    unittest.main()
