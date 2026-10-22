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
./start.exe          # 显示开启/关闭菜单
./start.exe start    # 启动已有容器；不存在则从本地镜像创建
./start.exe stop     # 停止容器，不删除容器和数据
```

若 Docker 镜像以 ZIP 包提供，先在宿主机运行 `./install-image.exe <镜像.zip>`。ZIP 内须包含 `docker save` 导出的 `.tar`（或 `.tar.gz`、`.tgz`、`.tar.bz2`、`.tar.xz`、`.tar.zst`）镜像归档；程序校验后流式导入 Docker，不将大镜像解压到磁盘。若 ZIP 内有多个归档，使用 `./install-image.exe <镜像.zip> --entry <ZIP内路径>` 选定一个。导入不会自动启动容器，之后运行 `./start.exe start`；必要时设置 `WORKBENCH_IMAGE` 为实际导入的镜像标签。此程序不是针对普通源码 ZIP 或 Dockerfile 的安装器。重新编译命令：`gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o install-image.exe docker_image_zip_installer.c`。

新建容器使用 4G `/dev/shm`。若当前已有的同名容器不是 4G，程序会拒绝直接启动，并提示迁移方法；不会自动停止、删除或覆盖旧容器。迁移前必须核对容器内未挂载到宿主机的历史分析产物，直接从镜像重建不会自动带入这些产物。默认容器名为 `syzkaller-workbench`，默认镜像为 `syzkaller-workbench:ready-kernel229-lvout715-shmfix-20261021`，可分别通过 `WORKBENCH_CONTAINER_NAME`、`WORKBENCH_IMAGE` 覆盖。若镜像尚未导入，可设置 `WORKBENCH_IMAGE_ARCHIVE` 指向 `docker save` 生成的镜像包。

需要重新编译可执行文件时：`gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o start.exe workbench_launcher.c`。旧文件名 `start.sh` 仅作为兼容链接保留，供旧版镜像入口使用。

Windows 本地预览：

```bat
start.bat
```

打开 <http://127.0.0.1:8080>。
