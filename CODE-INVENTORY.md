# `/media/iotteam/hd` 代码目录索引

盘点基于容器 `c9544c323dbd` 当前挂载视图。这个目录里存在源代码、工作副本和生成物；文件夹名中的日期/版本通常代表独立实验快照，不能只按名称判断可删除或可覆盖。

## 1. 工作台应用

路径：`/media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013`

| 路径 | 内容 |
|---|---|
| 根目录 `server.py`、`pipeline.py`、`*_bridge.py`、`*_query.py` | Python HTTP 后端、流水线调度、静态分析与 CodeQL 接口 |
| 根目录 `*.js`、`*.css`、`index.html` | 前端页面和样式 |
| `codeql_query/` | CodeQL 查询包、查询运行器与结果处理 |
| `config/` | 工作流、驱动、Linux 版本和工具路径配置 |
| `data/tasks/` | 任务快照、日志和分析结果；这是运行数据，不是源码 |
| `docker_query/` | CodeQL 查询相关部署/运行文件及挂载数据 |
| `static/` | 页面静态资源 |

应用入口为 `start.sh`（Linux）及 `server.py`。根目录 README 和 `PIPELINE.md` 记录了操作说明和各流水线阶段。

## 2. `/media/iotteam/hd/pyh/mi`：主要工具链与内核代码

| 路径 | 分类与说明 |
|---|---|
| `linux-5.15/`、`linux-7.1.5/` | Linux 内核源码 |
| `syzkaller/` | Syzkaller 源码及其构建产物 |
| `qemu/` | QEMU 源码树；另有 `build-qemu-exp/` 构建目录 |
| `tools/SVF/` | SVF 源码、`Release-build/` 构建结果 |
| `ana/StateFuzz/` | StateFuzz / sv-collector 分析源码与结果目录 |
| `afl-proxy/` | AFL proxy、stage2、guest kernel patch 等组件；`proxy/build/` 和 `stage2/build/src/` 含共享库 |
| `llm_probe/` | Probe 流程及模型调用脚本 |
| `scripts/` | 分析、驱动修复及辅助脚本 |
| `linux-5.15/`、`linux-7.1.5/` | 两个内核版本的完整源码工作树 |
| `analyse/`、`lvout-5.15/`、`out/` | bitcode / 分析输出或构建产物，不应与原始源码混淆 |
| `docker/`、`image/` | 容器和虚拟机镜像相关配置/资源 |

该目录的一级子目录全集（按盘点时状态）：

```text
afl-proxy  ana  analyse  build-qemu-exp  docker  image  linux-5.15
linux-7.1.5  llm_probe  lvout-5.15  out  qemu  scripts  syzkaller  tools
```

## 3. `/media/iotteam/hd/lx`：静态查询与内核复现工作区

`linux-6.18.1/`、`linux-7.2.6/`、`linux-mainline/` 是内核源码工作区。`*-repro-*`、`*-initramfs-*`、`*-kasan-*`、`*-module-*` 等目录是复现工程或其输入；`codeql/`、`codeql-db/`、`linux-mainline-codeql-db/` 等是 CodeQL 工具/数据库；`static-query*`、`ops*`、`deepfound/`、`codeql_test/` 中既有代码工作副本，也有查询结果、测试数据库和运行记录。

盘点时一级目录全集：

```text
.agents  .codex  .git  __pycache__  codeql  codeql-db  codeql_test
deepfound  download  hvc-repro-initramfs-20261019  hvc-repro-module-20261019
ioat-mainline-kasan-repro-20261019  linux-6.18.1  linux-7.2.6  linux-mainline
linux-mainline-build-repro-20261019  linux-mainline-codeql-build
linux-mainline-codeql-db  linux-mainline-codeql-db.failed-quoted-path
linux-mainline-repro-20261019  megasas-repro  ops
ops-level4-concurrency-20261019-000924  ops-migrated-6.18.1-8db-20261018-233435
pch-uart-rx-kasan-test-20261019  sf-pdma-race-repro-20261019
sf-pdma-repro-initramfs-20261019  static-query  static-query-6.1
static-query-results  static-query-results-7modules-20261008
static-query-test-results-6.1  static-query-test-run-6.1.QDos4Y
static-query-test-run-6.1.zo42sU  static-query-testdb-6.1
static-query-testdb-6.1-ops  static-query-testdb-6.1-ops-callbacks
static-query-testdb-6.1-ops-final  static-query-testdb-6.1-ops-identity
static-query-testdb-6.1-ops-identity-v2  static-query-testdb-6.1-ops-transfers
static-query-testdb-6.1-ops-transfers-v2  static-query-testdb-6.1-simple-transfers
static-query-web-20260910
static-query-web-20260910-6.18.1-8drivers-20261017
static-query-web-20260910-6.18.1-8drivers-20261017-clean-rebuild-20261017
static-query-web-20260910-6.18.1-8drivers-20261017-clean-rebuild-20261017-current-models
static-query-web-20260910-6.18.1-8drivers-20261017-rebuild-20261017
static-query-web-20260910-6.18.1-bluetooth-hci-free-dev-20261017
static-query-web-20260910-6.18.1-llm-triage-20261017
static-query-web-20260910-results-7.2.6-20261017
static-query.backup-20261007  timbuart-patch-repro-20261019
timbuart-tasklet-initramfs-20261019  timbuart-tasklet-repro-20261019-src
uaf_make  uafx
```

## 4. 分类和维护建议

1. 将原始源码、构建目录、任务结果/数据库分开识别；当前目录结构已经包含大量历史实验快照，不宜对它们统一重命名。
2. 以各项目自己的 README、构建文件和 Git 元数据判断版本；某些实验目录是复制品或结果集，不一定是独立 Git 仓库。
3. 对外说明可从本文件的三块入口开始；工具、版本、环境变量及共享库位置见 [环境清单](ENVIRONMENT-MANIFEST.md)。

