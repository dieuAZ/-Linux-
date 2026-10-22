# Syzkaller Workbench Offline

容器内代码树及工具/共享库清单见 [代码与环境总索引](CODE-AND-ENV-INDEX.md)。

完全离线的 Syzkaller Web 工作台骨架。运行时不依赖 Cloudflare、CDN、在线字体、Node.js 或任何 Python 第三方包。

## 启动

Linux 宿主机（`start.sh` 为已编译的可执行文件）：

```bash
./start.sh          # 显示开启/关闭菜单
./start.sh start    # 启动已有容器；不存在则从本地镜像创建
./start.sh stop     # 停止容器，不删除容器和数据
```

若 Docker 镜像以 ZIP 包提供，先在宿主机运行 `./install-image <镜像.zip>`。ZIP 内须包含 `docker save` 导出的 `.tar`（或 `.tar.gz`、`.tgz`、`.tar.bz2`、`.tar.xz`、`.tar.zst`）镜像归档；程序校验后流式导入 Docker，不将大镜像解压到磁盘。若 ZIP 内有多个归档，使用 `./install-image <镜像.zip> --entry <ZIP内路径>` 选定一个。导入不会自动启动容器，之后运行 `./start.sh start`；必要时设置 `WORKBENCH_IMAGE` 为实际导入的镜像标签。此程序不是针对普通源码 ZIP 或 Dockerfile 的安装器。重新编译命令：`gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o install-image docker_image_zip_installer.c`。

新建容器使用 4G `/dev/shm`。若当前已有的同名容器不是 4G，程序会拒绝直接启动，并提示迁移方法；不会自动停止、删除或覆盖旧容器。迁移前必须核对容器内未挂载到宿主机的历史分析产物，直接从镜像重建不会自动带入这些产物。默认容器名为 `syzkaller-workbench`，默认镜像为 `syzkaller-workbench:ready-kernel229-lvout715-shmfix-20261021`，可分别通过 `WORKBENCH_CONTAINER_NAME`、`WORKBENCH_IMAGE` 覆盖。若镜像尚未导入，可设置 `WORKBENCH_IMAGE_ARCHIVE` 指向 `docker save` 生成的镜像包。

需要重新编译可执行文件时：`gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o start.sh workbench_launcher.c`。

Windows 本地预览：

```bat
start.bat
```

打开 <http://127.0.0.1:8080>。

## 配置真实工作流

一键启动由本目录的 `pipeline.py` 调度，按静态分析、Probe、Fuzz、可选 Seed 的顺序运行，不需要外部 `run_workflow.py`。服务器路径与并发数在 `config/system.json` 中配置；详细行为见 `PIPELINE.md`。

Linux 5.15 的八个目标已登记在 `config/static_analysis_params.json`，源码根目录为 `/media/iotteam/hd/pyh/mi/vm/linux-5.15`。静态分析所需的 `/media/iotteam/hd/pyh/mi/analyse/lvout-linux-5.15` 当前尚不存在；生成对应 LLVM bitcode 后，一键启动页面才会将这些目标标记为就绪。Probe 还需要在系统配置页填写 LLM API Key。

## 四个独立阶段

页面和任务被拆分为：

```text
静态分析 → 驱动 Probe → Syzkaller Fuzz → 种子生成
```

每一步都可以单独创建、查看日志和重试。

## CodeQL 静态查询

`CodeQL 静态查询` 是与上述动态测试流水线相互独立的模块，不进入一键启动流程。页面可独立选择 Linux、驱动以及 IRQ、hrtimer、kthread、NAPI、RCU、tasklet、timer、workqueue 八类查询。

最新查询包位于 `codeql_query/`，Web 后端通过统一入口启动：

```bash
python3 codeql_query/run_static_query.py \
  --task-id <task_id> \
  --task-dir <task_dir>
```

任务配置快照位于 `<task_dir>/snapshot/configs/static_query.json`，状态和产物清单分别位于任务的 `artifacts/codeql/status.json` 与 `artifacts/codeql/artifacts.json`，最终融合结果为 `artifacts/codeql/merged_semantic_unique.csv`。CodeQL 程序位置、数据库目录和资源限制在 `config/system.json` 的 `codeql_query` 节点配置。

## 目标清单

静态分析和 Probe 页面读取固定文件 `config/static_analysis_params.json`。该文件同时保存 Linux 源码根目录、bitcode 根目录、框架 bitcode 集合以及各驱动的路径映射。格式为：

```json
[
  {"linux-7.1.5": ["erdma", "irdma"]},
  {"linux-6.6": ["e1000", "vmxnet3"]}
]
```

设备清单也可以携带 PCI 标识，但页面和 `/api/catalogs/probe` 只显示
`name`。创建任务时，后端会把对应的 `vid`、`pid` 以及可用的
`subvid`、`subpid` 写入任务的 Probe 配置，供 QEMU/SFP 使用：

```json
[
  {
    "linux-7.1.5": [
      {"name": "erdma", "vid": "0x1ded", "pid": "0x107f"}
    ]
  }
]
```

Probe 成功后由 `probe_completed_list.py` 自动写入 `config/probe_completed.json`。清单不是简单的驱动名称列表，而是按 Linux 版本保存源码根目录和驱动元数据：

```json
[
  {
    "linux-7.1.5": {
      "linux_path": "/media/iotteam/hd/pyh/mi/linux-7.1.5",
      "drivers": [
        {
          "name": "qxl",
          "type_tags": ["drm", "gpu", "pci", "ttm"],
          "vid": "0x1b36",
          "pid": "0x0100"
        }
      ]
    }
  }
]
```

Probe 成功时，后端从静态分析设备配置读取 VID/PID，从驱动源码路径推导类型标签，并从 Linux 版本配置得到 `linux_path`，然后原子更新该文件。同一 Linux/驱动会更新已有条目而不会重复添加。Fuzz 页面读取其中的驱动名称，并与已完成静态分析任务取交集，因此两个前置阶段都成功后才能创建 Fuzz。旧工具使用的 `config/B.json` 仍会同步更新。

Fuzz 成功后写入 `config/C.json`，种子生成页面从 `C.json` 读取目标。`B.json` 和 `C.json` 初始都为空：

```json
[]
```

当 Probe 任务上报 `COMPLETED`、`READY_FOR_FUZZ`，或者三层校验全部通过时，后端自动把对应目标原子写入 `B.json`。Fuzz 上报 `COMPLETED` 后自动写入 `C.json`。同一目标不会重复写入。

Probe 页面填写 LLM API 地址、模型名称和 API Key 后，服务器只在 Probe 任务中生成 `probe_static.json` 和 `probe_deep.json`。路径、VID/PID、静态分析输出文件和设备模型路径由配置自动拼接。

Syzkaller 系统调用集合硬编码在 `config/syzkaller_syscall_sets.json`：`common` 是 `read`、`close`、`write`，`tag_sets` 保存 DRM、`gpu/drm/tiny`、SCSI、媒体、Framebuffer 等框架集合，`driver_sets` 只保存 Syzkaller 中明确对应具体驱动的描述，例如 `i915`、`pvpanic_pci` 和 `r592`。DRM 通用集合与 `gpu/drm/tiny` 集合按描述文件中的调用划分且不重复；没有具体 Syzkaller 描述的驱动不会从其他驱动复制调用。

因此 Probe 和 Fuzz 是两个独立任务：Probe 已经成功的目标可以重复创建 Fuzz 任务，不需要重新执行 Probe。任务编号由后端全局自动生成，页面不允许手动输入。

## 本地 API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/health` | 本地服务和工作流配置状态 |
| `GET` | `/api/system` | 端口范围及运行模式 |
| `GET` | `/api/catalogs/probe` | 读取 `config/static_analysis_params.json` |
| `GET` | `/api/catalogs/static` | 静态分析可选目标 |
| `GET` | `/api/catalogs/fuzz` | 静态分析成功目标与 `B.json` 的交集 |
| `GET` | `/api/catalogs/seed` | 读取 `config/C.json` |
| `GET` | `/api/tasks` | 任务列表 |
| `POST` | `/api/tasks` | 创建任务 |
| `GET` | `/api/tasks/{id}` | 任务详情及最新上报数据 |
| `POST` | `/api/tasks/{id}/start` | 分配端口并启动真实工作流 |
| `POST` | `/api/tasks/{id}/stop` | 终止本地工作流进程组 |
| `POST` | `/api/tasks/{fuzz_id}/seed` | 从正在运行的 Fuzz 提前派生 Seed 任务 |
| `GET` | `/api/tasks/{id}/logs` | 获取真实 stdout/stderr |
| `GET` | `/api/tasks/{id}/logs/static` | 获取 `svf.log` 和 `collector.log` |
| `GET` | `/api/tasks/{id}/logs/fuzz` | 获取 `fuzz.log` |
| `GET` | `/api/tasks/{id}/logs/seed` | 获取 `seed.log` |
| `GET` | `/api/tasks/{id}/events` | 获取任务事件 |
| `POST` | `/api/tasks/{id}/report` | 工作流上报阶段与真实指标 |

### 创建任务

```json
{
  "task_type": "STATIC_ANALYSIS | PROBE | FUZZ | SEED",
  "linux_version": "linux-7.1.5",
  "driver": "irdma",
  "extra_enabled": false
}
```

### 工作流上报

本地工作流可以在每个阶段向同机接口提交实际状态：

```bash
curl -X POST http://127.0.0.1:8080/api/tasks/<task_id>/report \
  -H 'Content-Type: application/json' \
  -d @report.json
```

`report.json` 示例：

```json
{
  "stage": "FUZZ",
  "status": "RUNNING",
  "probe_modes": {
    "static": {"status": "PASSED", "content": {}, "skip_reason": null},
    "deep": {"status": "SKIPPED", "content": null, "skip_reason": "ACTIVATED_AFTER_STATIC"},
    "extra": {"status": "PASSED", "content": {}, "skip_reason": null}
  },
  "validation": {
    "driver_binding": {"status": "PASSED", "content": {}, "error": null},
    "sysfs_interfaces": {"status": "PASSED", "content": {}, "error": null},
    "open_test": {"status": "PASSED", "content": {}, "error": null}
  },
  "static_analysis": {
    "svf": {"status": "PASSED"},
    "collector": {"status": "PASSED"}
  },
  "metrics": {
    "coverage_pcs": 184672,
    "corpus_count": 2846,
    "crash_count": 7
  },
  "fuzz": {
    "status": "RUNNING",
    "window_minutes": 30,
    "new_pcs_in_window": 28,
    "restart_attempts": 0
  },
  "seed": {"status": "WAITING"}
}
```

Fuzz 工作流按以下阶段上报并执行：

```text
Syzkaller Fuzz
      ↓ 收敛或达到本轮三小时上限
自动 Seed Generator
      ↓
下一轮 Syzkaller Fuzz
```

自动循环规则：

1. Fuzz 因覆盖率收敛或达到本轮最长时间而停止；
2. 保留原来的 corpus、workdir 和任务端口；
3. 自动执行 Seed Generator；
4. Seed 成功后循环编号加一；
5. 重新记录 `fuzz_started_at`，本轮三小时时限从零计算；
6. 清空上一轮覆盖率采样，重新记录 `convergence_window_started_at`；
7. 使用原 workdir 启动下一轮 Fuzz。

工作流应上报循环状态：

```json
{
  "stage": "FUZZ",
  "status": "RUNNING",
  "cycle": {
    "index": 2,
    "phase": "FUZZING",
    "fuzz_started_at": "2026-08-17T18:00:00+08:00",
    "convergence_window_started_at": "2026-08-17T18:00:00+08:00",
    "previous_stop_reason": "CONVERGED"
  },
  "fuzz": {"status": "RUNNING"},
  "seed": {"status": "COMPLETED"}
}
```

`cycle.phase` 可使用 `FUZZING`、`GENERATING_SEED` 和 `RESTARTING_FUZZ`。自动循环由服务器上的工作流程序负责执行，Web 后端保存并展示其真实上报状态。

### Fuzz 期间提前生成种子

种子生成页面不允许手动选择 Linux 版本或设备，只显示当前状态为 `STARTING`、`RUNNING` 或 `READY_FOR_FUZZ` 的 Fuzz 任务。点击“提前生成种子”后调用：

```text
POST /api/tasks/<fuzz_task_id>/seed
```

新 Seed 任务自动继承父 Fuzz 的：

- Linux 版本和驱动；
- Manager 端口；
- `parent_task_id`；
- 工作流通过 `parent_task_id` 定位的 workdir、corpus 和覆盖率结果。

工作流命令可以使用 `{parent_task_id}` 占位符。人工提前 Seed 与自动循环 Seed 不同：它作为独立子任务执行，不停止父 Fuzz，也不修改父 Fuzz 的循环编号、三小时开始时间和覆盖率收敛窗口。

工作流应分别把日志写入任务目录的 `logs/svf.log`、`logs/collector.log`、`logs/fuzz.log` 和 `logs/seed.log`，页面会按页签读取这些真实文件。

服务端只接受白名单字段，并以临时文件加原子替换方式保存最新报告。

## 本地数据

首次启动会自动创建：

```text
data/tasks.db
data/tasks/<slug>/
├── logs/workflow.log
├── artifacts/
├── events.jsonl
└── snapshot/
    ├── task.json
    ├── commands.json
    ├── report.json
    └── configs/
```

所有实验数据都保存在本机。项目不包含任何云端部署配置。

## 当前边界

本项目已经提供真实前后端通信、任务记录、端口分配、进程启动/停止、日志和状态上报接口。具体的 SVF、Collector、Probe、QEMU、Syzkaller 和 Seed Generator 串联逻辑仍需要由你们服务器上的 `run_workflow.py` 实现，因为这些脚本和运行环境不在本项目中。
