"""CodeQL source-path and snapshot checks without launching analysis jobs."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class CodeqlSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.kernel = self.base / "linux-7.1.5"
        (self.kernel / "drivers" / "foo").mkdir(parents=True)
        (self.base / "outside").mkdir()
        (self.kernel / "drivers" / "link").symlink_to(self.base / "outside", target_is_directory=True)
        self.params = self.base / "static_analysis_params.json"
        self.params.write_text(json.dumps([{
            "linux-7.1.5": {"source_root": str(self.kernel), "drivers": []}
        }]), encoding="utf-8")
        self.settings = {"codeql_query": {
            "database_root": str(self.base / "databases"),
            "codeql_path": "/usr/bin/codeql",
            "kernel_root_by_version": {"linux-7.2.6": str(self.base / "outside")},
        }}
        paths = patch.multiple(server, STATIC_PARAMS=self.params, TASKS=self.base / "tasks",
                               LLM_SETTINGS=self.base / "llm_settings.json")
        paths.start()
        self.addCleanup(paths.stop)
        config = patch.object(server, "config", return_value=self.settings)
        config.start()
        self.addCleanup(config.stop)

    def test_catalog_and_source_validation(self):
        catalog = server.codeql_catalog()
        self.assertIn("drivers/foo", catalog["items"]["linux-7.1.5"])
        self.assertIn(".", catalog["items"]["linux-7.1.5"])
        self.assertNotIn("drivers/link", catalog["items"]["linux-7.1.5"])
        self.assertEqual(server.validate_codeql_source_path("linux-7.1.5", "drivers/foo"),
                         (self.kernel, "drivers/foo"))
        with self.assertRaises(ValueError):
            server.validate_codeql_source_path("linux-7.1.5", "../outside")
        with self.assertRaises(ValueError):
            server.validate_codeql_source_path("linux-7.1.5", "drivers/link")

    def test_codeql_snapshot_keeps_source_relative_path_and_ops(self):
        task = {"id": "task-1", "slug": "codeql_query_linux-7.1.5_drivers__foo_001",
                "linux_version": "linux-7.1.5", "driver": "drivers/foo"}
        (server.TASKS / task["slug"] / "snapshot" / "configs").mkdir(parents=True)
        server.prepare_codeql_config(task, {"queries": ["ops"], "reuse_database": False})
        path = server.TASKS / task["slug"] / "snapshot" / "configs" / "static_query.json"
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(snapshot["kernel_root"], str(self.kernel))
        self.assertEqual(snapshot["driver_dir"], str(self.kernel))
        self.assertEqual(snapshot["source_relative_path"], "drivers/foo")
        self.assertEqual(snapshot["build_mode"], "in_tree")
        self.assertEqual(snapshot["queries"], ["ops"])
        self.assertTrue(snapshot["llm_review"])
        self.assertEqual(snapshot["llm_settings_file"], str(server.LLM_SETTINGS.resolve()))
        self.assertFalse(snapshot["reuse_database"])


if __name__ == "__main__":
    unittest.main()
