# 容器代码与环境索引

盘点对象：Docker 容器 `c9544c323dbd`（完整 ID 前缀匹配，容器名 `syzkaller-workbench`），容器内 `/media/iotteam/hd`。盘点时间：2026-10-22。详细目录和环境明细见：

- [代码目录索引](CODE-INVENTORY.md)
- [环境、工具与动态库清单](ENVIRONMENT-MANIFEST.md)

## 整理原则

该挂载点同时包含 Linux 内核源码、多个代码实验副本、CodeQL 数据库、LLVM bitcode、构建目录和复现产物。为避免破坏不同实验版本和任务数据，本次以目录索引、源码/产物分类、路径说明的方式整理，没有移动或删除已有文件。

## 三个主要代码区

| 容器路径 | 用途 |
|---|---|
| `/media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013` | Syzkaller Web 工作台，含 Python 服务、前端静态文件、工作流、CodeQL 查询包、配置和任务数据 |
| `/media/iotteam/hd/lx` | Linux 内核、CodeQL 查询/数据库、静态查询工作副本、内核复现工程与结果 |
| `/media/iotteam/hd/pyh/mi` | Linux 5.15/7.1.5、Syzkaller、QEMU、SVF、AFL proxy、StateFuzz 和分析脚本 |

## 环境概况

容器运行 Debian 12。运行时使用 Python 3.10.22；系统 Python 3.11.2 也存在。LLVM 15、CodeQL 2.25.0 和系统 QEMU 7.2.22 已安装。自定义 LLVM 14 clang 文件位于 `/opt/clang14`，但当前启动环境没有将 `/opt/clang14/lib` 加入 `LD_LIBRARY_PATH`，因此直接执行 `/opt/clang14/bin/clang` 会因找不到 `libclang-cpp.so.14` 而失败。详见环境清单。

