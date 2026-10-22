"""Integration checks use only temporary storage and localhost, never real jobs."""
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import server


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        (root/'config').mkdir()
        (root/'config'/'test.config').write_text('{}')
        self.patch=patch.multiple(server,ROOT=root,DATA=root/'data',TASKS=root/'data'/'tasks',DB_PATH=root/'data'/'tasks.db',
                                  PROBE_TARGETS=root/'targets.json',PIPELINES=None)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.catalog=patch.object(server,'read_catalog',return_value={'linux':['one','two']})
        self.catalog.start();self.addCleanup(self.catalog.stop)
        self.available=patch.object(server,'available_driver_catalog',return_value={'linux':['one','two']})
        self.available.start();self.addCleanup(self.available.stop)
        self.llm=patch.object(server,'llm_settings',return_value={'has_api_key':True})
        self.llm.start();self.addCleanup(self.llm.stop)
        server.init_storage()
        self.runner=patch.object(server.PIPELINES,'run')
        self.runner.start();self.addCleanup(self.runner.stop)
        self.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.base=f'http://127.0.0.1:{self.http.server_port}'
    def request(self,path,payload=None):
        req=urllib.request.Request(self.base+path,data=json.dumps(payload).encode() if payload is not None else None,
                                   headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req,timeout=3) as response:
                return response.status,json.load(response)
        except urllib.error.HTTPError as response:
            with response:
                return response.code,json.load(response)
    def test_create_list_conflict_stop(self):
        code,item=self.request('/api/pipelines',{'linux_version':'linux','driver':'one'})
        self.assertEqual(code,201)
        self.assertEqual(self.request('/api/pipelines')[1]['items'][0]['id'],item['id'])
        self.assertEqual(self.request('/api/pipelines',{'linux_version':'linux','driver':'one'})[0],409)
        self.assertEqual(self.request(f"/api/pipelines/{item['id']}/stop",{})[1]['status'],'STOPPING')
    def test_api_validation_and_missing(self):
        self.assertEqual(self.request('/api/pipelines',{'linux_version':'linux','driver':['one','two']})[0],409)
        self.assertEqual(self.request('/api/pipelines/missing/stop',{})[0],404)
    def test_snapshot_not_public_config(self):
        task={'id':'x','slug':'fuzz_linux_one_001','linux_version':'linux','driver':'one','task_type':'FUZZ','manager_port':56741}
        folder=server.task_dir(task)/'snapshot'/'configs'
        folder.mkdir(parents=True)
        (folder/'fuzz.config').write_text('{}')
        with patch.object(server,'config',return_value={'backend':{'root':'/srv/mi'}}):
            command,cwd=server.build_command(task)
        self.assertIn(f"{(folder/'fuzz.config').resolve()}:/tmp/linux_one.config:ro",command)
        self.assertIn('/srv/mi/docker/fuzz6/runtime/linux:/opt/fuzz6/runtime/linux:ro',command)

    def test_telemetry_endpoint_reads_task_log(self):
        folder=Path(self.temp.name)/'sample-task'
        (folder/'logs').mkdir(parents=True)
        (folder/'snapshot'/'configs').mkdir(parents=True)
        (folder/'logs'/'workflow.log').write_text('2026/10/13 07:18:10 corpus=175 coverage=7912 exec total=8632 (15/sec)\n',encoding='utf-8')
        (folder/'snapshot'/'configs'/'fuzz.config').write_text('{"vm":{"count":4}}',encoding='utf-8')
        task={'id':'sample-task','task_type':'FUZZ','status':'RUNNING','started_at':'2026-10-13T07:00:00+08:00','finished_at':None}
        with patch.object(server,'get_task',return_value=task),patch.object(server,'task_dir',return_value=folder):
            code,data=self.request('/api/tasks/sample-task/telemetry')
        self.assertEqual(code,200)
        self.assertEqual(data['last']['coverage_pcs'],7912)
        self.assertEqual(data['configured_vms'],4)
        self.assertEqual(data['task_status'],'RUNNING')


if __name__=='__main__': unittest.main()
