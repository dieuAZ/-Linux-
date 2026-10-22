# 独立 Docker 运行环境

这个版本把工作台后端、Python 运行时、编译工具链、Linux 7.1.5 源码和 bitcode、SVF/KAMain、Syzkaller、QEMU、Probe、CodeQL CLI、CodeQL 数据库和必要查询目录构建进同一个镜像。

构建脚本不会打包历史 Fuzz 结果、备份镜像或宿主机 Docker socket。Fuzz 改为直接在工作台容器内启动 Syzkaller，不再依赖 `mi-syzkaller-fuzz6:latest` 子镜像。

## 构建与启动

若本机已经有 `syzkaller-workbench:standalone-20261021` 镜像，可离线补入宿主机的 GCC 11、`libstdc++`、`libasan`、项目 QEMU 的动态库及 Python 3.10 的 OpenAI SDK，并将 GCC 11 设为容器默认编译器：

```bash
./docker_query/build-offline-runtime.sh
```

生成的镜像为 `syzkaller-workbench:portable-20261021`。脚本会在无宿主机目录挂载的容器中检查 GCC 11、KAMain、Syzkaller 和 QEMU。当前没有打包 `linux-7.2.6` 内核源码；该版本的 CodeQL 编译任务尚不能在脱离宿主机后执行。

完整资产约需 35GB 以上，镜像还需要额外构建空间。先确认宿主机具备 Docker、Linux 和 `/dev/kvm`：

```bash
docker info
test -e /dev/kvm
```

执行：

```bash
cd /media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013
chmod +x docker_query/docker-run.sh
./docker_query/docker-run.sh
```

启动后在仪表板中填写真实的 API Key。示例文字不能作为 Key；HTTP 请求头要求 Key 使用 ASCII 字符。
当前脚本默认使用 `syzkaller-workbench:ready-kernel229-keyfix-20261021`，并给 `/dev/shm` 分配 4 GiB。镜像内的 Linux 7.1.5 已执行 `make -j"$(nproc)" KCFLAGS=-DPROBE_FIX=1` 重新编译，同时关闭 `CONFIG_SERIAL_NUVOTON_MA35D1_CONSOLE` 以避免 QEMU 启动时无效串口控制台刷屏，并关闭 `CONFIG_FSL_BMAN_TEST`、`CONFIG_FSL_QMAN_TEST` 以避免 x86 虚拟机启动时的 BMan 自测 panic。QEMU 所需的宿主机动态库已复制到镜像内的 `/opt/qemu-libs`，并加入动态链接器搜索路径；镜像也包含 saa7134 的现有分析结果和 QEMU 源码、构建目录。

如果只需要构建镜像、不启动服务：

```bash
BUILD_IMAGE=1 BUILD_ONLY=1 IMAGE=syzkaller-workbench:standalone-20261021 ./docker_query/docker-run.sh
```

## 环境变量

| 变量 | 默认值 | 作用 |
|---|---|---|
| `WORKBENCH_DIR` | 当前工程目录 | 工作台代码来源目录 |
| `MI_ROOT` | `/media/iotteam/hd/pyh/mi` | Linux、bitcode、SVF、Syzkaller、QEMU 等资产根目录 |
| `LX_ROOT` | `/media/iotteam/hd/lx` | CodeQL、数据库和查询资产根目录 |
| `IMAGE` | `syzkaller-workbench:ready-kernel229-keyfix-20261021` | 镜像名称 |
| `DATA_DIR` | `docker_query/data` | 宿主机持久化任务数据目录 |
| `SHM_SIZE` | `4g` | 容器 `/dev/shm` 容量；Probe/QEMU 的 `create_shm` 需要超过默认 64 MB |
| `BUILD_IMAGE` | `0` | 是否先构建旧版完整镜像 |
| `BUILD_ONLY` | `0` | 只构建镜像，不启动容器；无需 KVM |
| `LIBSTDCXX_SOURCE` | `/usr/lib/x86_64-linux-gnu/libstdc++.so.6` | 构建时提供含 `GLIBCXX_3.4.32` 的宿主机动态库 |
| `REQUIRE_KVM` | `1` | 是否强制检查 `/dev/kvm` |
| `LLM_API_KEY` | 空 | 运行时传入，不写入镜像 |
| `LLM_API_BASE` | `https://api.deepseek.com` | LLM API 地址 |
| `LLM_MODEL` | `deepseek-v4-pro` | LLM 模型名 |

## 仍然需要宿主机提供的部分

- Docker daemon：只用于构建和启动主容器，不再用于 Fuzz 子容器。
- Linux 内核：容器共享宿主机内核，不能把宿主机内核本身打包进 Docker 镜像。
- `/dev/kvm`：QEMU Fuzz 需要硬件加速；没有 KVM 时不能保证完整 Fuzz 能力。
- LLM 网络和 API Key：Probe 需要访问配置的 API 服务。

因此这是“单镜像携带全部软件和分析资产”，不是脱离 Linux 内核和硬件的单一 ELF 可执行文件。

KAMain 需要 `GLIBCXX_3.4.32`，Debian bookworm 自带的 libstdc++ 不提供该符号。构建脚本会复制宿主机上较新的 libstdc++ 到镜像，并只给 KAMain 设置该库的搜索路径；镜像构建时会检查全部动态库依赖。若宿主机默认库仍太旧，可将 `LIBSTDCXX_SOURCE` 指向兼容 Debian bookworm（glibc 2.36）的新版 `libstdc++.so.6`。
