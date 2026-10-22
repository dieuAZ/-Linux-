# 崇明鸟

容器内代码树及工具/共享库清单见 [代码与环境总索引](CODE-AND-ENV-INDEX.md)。

崇明鸟——面向 Linux 内核缺陷的静态分析工作台，集成 CodeQL 并发查询、语义去重与 LLM 分诊。

## 仓库与交付

仓库地址：https://github.com/dieuAZ/崇明鸟

本仓库只包含源码、查询和文档。以下内容体积过大，而比赛对提交文件大小有限制（不超过 500 MB），无法放入仓库，因此改为链接分发：

- Docker 镜像（数十 GB）
- CodeQL CLI（约 1.7 GB）
- Linux 内核源码（多版本）

## 启动

Linux 宿主机（`start.exe` 是 Linux ELF 可执行文件；`.exe` 只是文件名后缀，不代表 Windows 程序）：

```bash
./start.exe          # 自动启动已有容器并检查网页服务；无容器则创建
./stop.exe           # 停止容器，不删除容器和数据
```

默认镜像标签为 `ghcr.io/dieuaz/chongmingniao:20261022`。若目标容器已存在，`start.exe` 会复用并启动它，检查 <http://127.0.0.1:8080>；网页服务未响应时会尝试在容器内启动 `server.py`。没有容器但已有镜像时会创建容器；两者都没有时会先从 GHCR 自动拉取镜像。若镜像为私有，须先登录 GHCR。新容器不挂载宿主机的工作台、LX 或数据目录，使用镜像内打包的工作台代码、CodeQL、Linux 7.2.6 源码及初始任务数据。后续任务数据保存在容器可写层，停止/启动容器不会丢失，删除容器前则必须另行备份。

旧版离线 ZIP 仍可由 `./install-image.exe <镜像.zip>` 导入，但使用 GHCR 镜像时无需运行此程序。ZIP 内须包含 `docker save` 导出的 `.tar`（或 `.tar.gz`、`.tgz`、`.tar.bz2`、`.tar.xz`、`.tar.zst`）镜像归档；程序校验后流式导入 Docker，不将大镜像解压到磁盘。若 ZIP 内有多个归档，可使用 `--entry <ZIP内路径>`。重新编译命令：`gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o install-image.exe docker_image_zip_installer.c`。

新建容器使用 4G `/dev/shm`。同名旧容器会保留并复用，即使它使用其他镜像；旧容器 `/dev/shm` 不是 4G 时只会警告，因为 Docker 无法原地修改。默认容器名为 `syzkaller-workbench`，可分别通过 `WORKBENCH_CONTAINER_NAME`、`WORKBENCH_IMAGE` 覆盖。若有本地 `docker save` 归档，也可设置 `WORKBENCH_IMAGE_ARCHIVE` 指向该归档。`./start.exe start` 和 `./start.exe stop` 仍可兼容使用。

需要重新编译可执行文件时：`gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o start.exe workbench_launcher.c`，再运行 `gcc -std=c11 -O2 -Wall -Wextra -Werror -static -DWORKBENCH_STOP_ONLY -o stop.exe workbench_launcher.c`。旧文件名 `start.sh` 仅作为兼容链接保留，供旧版镜像入口使用。

Windows 本地预览：

```bat
start.bat
```

打开 <http://127.0.0.1:8080>。
