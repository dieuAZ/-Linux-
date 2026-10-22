# 容器环境、工具与动态库清单

盘点对象为容器 `c9544c323dbd3d15c3932f081d71003be2d40225d1781d650b60b829246f156b`，容器名 `syzkaller-workbench`，镜像名 `syzkaller-workbench:ready-kernel229-lvout715-shmfix-20261021`。系统为 Debian GNU/Linux 12 (bookworm)。以下路径均为容器内部路径；版本信息取自程序 `--version`、运行时横幅或共享库 SONAME。SONAME 只代表 ABI 主版本，不等于上游完整发行版本。

## 环境变量

| 变量 | 当前值/用途 | 备注 |
|---|---|---|
| `PATH` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 不包含 `/usr/lib/llvm-15/bin` 和 `/opt/clang14/bin` |
| `LD_LIBRARY_PATH` | `/opt/kamain-lib:/opt/workbench-runtime:/media/iotteam/hd/pyh/mi/afl-proxy/proxy/build:/media/iotteam/hd/pyh/mi/afl-proxy/stage2/build/src` | 进程运行时共享库搜索目录；不含 `/opt/clang14/lib` 和 `/opt/qemu-libs` |
| `PATH_PREFIX` | `/usr/lib/llvm-15/bin` | 配置给分析流程的 LLVM 15 工具目录 |
| `LLVM_LINK` | `/usr/bin/llvm-link-15` | bitcode 链接器 |
| `PYTHON_VERSION` | `3.10.22` | 容器构建/应用选用版本；位于 `/usr/local/bin/python3` |
| `PYTHONUNBUFFERED` | `1` | Python 标准输出不缓冲 |
| `PYTHONDONTWRITEBYTECODE` | `1` | 禁止生成 `.pyc` 文件 |
| `SVF_ROOT` | `/media/iotteam/hd/pyh/mi/tools/SVF` | SVF 源码根目录 |
| `SVF_BUILD` | `/media/iotteam/hd/pyh/mi/tools/SVF/Release-build` | SVF 构建目录 |
| `KAMAIN` | `/media/iotteam/hd/pyh/mi/ana/StateFuzz/sv-collector/build/lib/KAMain` | sv-collector 使用的 KAMain 路径 |
| `WORKBENCH_FUZZ_MODE` | `local` | 工作台 fuzz 模式 |
| `LLM_API_KEY` | 空 | 环境变量已定义但为空；清单不记录任何凭据值 |
| `HOME` | `/root` | 容器内 root 用户主目录 |
| `PWD` | `/media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013` | 服务进程工作目录 |
| `LANG` | `C.UTF-8` | 语言环境 |
| `DEBIAN_FRONTEND` | `noninteractive` | Debian 软件包安装模式 |
| `HOSTNAME` | `mirukj` | 容器主机名 |
| `GPG_KEY` | 已设置，值省略 | 镜像构建元数据，不用于项目运行说明 |

`config/system.json` 在启动静态分析子进程时还会注入 `GENERATE_PAIR_DENY=1`、`PYTHONUNBUFFERED=1`、`LLVM_LINK`、`SVF_ROOT`、`SVF_BUILD` 和 `PATH_PREFIX`。

## 命令行工具

| 名称 | 版本 | 安装路径 |
|---|---|---|
| Debian | 12 (bookworm) | 容器基础系统 `/etc/os-release` |
| GCC | 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04 构建) | `/usr/local/bin/gcc` |
| Python (应用默认) | 3.10.22 | `/usr/local/bin/python3`、`/usr/local/bin/pip3` (pip 23.0.1) |
| Python (系统) | 3.11.2 | `/usr/bin/python3` |
| LLVM / llvm-link | 15.0.6 | `/usr/bin/llvm-*`; `llvm-link-15` 为 `/usr/bin/llvm-link-15` |
| CMake | 3.25.1 | `/usr/bin/cmake` |
| GNU Make | 4.3 | `/usr/bin/make` |
| Ninja | 1.11.1 | `/usr/bin/ninja` |
| Git | 2.39.5 | `/usr/bin/git` |
| QEMU system x86_64 | 7.2.22 (Debian `1:7.2+dfsg-7+deb12u18+b3`) | `/usr/bin/qemu-system-x86_64` |
| CodeQL CLI | 2.25.0 | `/media/iotteam/hd/lx/codeql/codeql` |
| clang 14 | 14.0.0-1ubuntu1.1 | `/opt/clang14/bin/clang`；执行时需能加载 `/opt/clang14/lib` 中的依赖 |
| SVF `wpa` | 版本号未由 `--version` 提供 | `/media/iotteam/hd/pyh/mi/tools/SVF/Release-build/bin/wpa` |
| SVF backward analyzer | 自定义构建；无版本横幅 | `/media/iotteam/hd/pyh/mi/scripts/analyse/svf_backend/build/svf_backward_analyzer` |
| Syzkaller `syz-manager` | 自定义构建；无版本横幅 | `/media/iotteam/hd/pyh/mi/syzkaller/bin/syz-manager` |

当前 `LD_LIBRARY_PATH` 没有 `/opt/clang14/lib`。因此直接执行 clang 14 会报找不到 `libclang-cpp.so.14`；临时把 `/opt/clang14/lib` 加入进程库搜索路径后，版本输出为 `Ubuntu clang version 14.0.0-1ubuntu1.1`。

## Python 安装包

工作台 README 声明 Web 服务运行只依赖 Python 标准库；`openai` SDK 是 Probe/LLM 调用脚本的可选依赖，不是网页服务本身的强制依赖。容器 Python 3.10 的 site-packages 路径为 `/usr/local/lib/python3.10/site-packages`。

| 包名 | 当前版本 | 当前环境状态 |
|---|---:|---|
| `openai` | 2.53.0 | 已安装 |
| `anyio` | 4.14.2 | 已安装 |
| `httpx` | 0.28.1 | 已安装，但缺 `certifi` 和 `idna` |
| `httpcore` | 1.0.9 | 已安装，但缺 `certifi` |
| `jiter` | 0.16.0 | 已安装 |
| `pydantic` | 2.13.4 | 已安装 |
| `pydantic-core` | 2.46.4 | 已安装 |
| `annotated-types` | 0.8.0 | 已安装 |
| `typing-inspection` | 0.4.2 | 已安装 |
| `typing-extensions` | 4.16.0 | 已安装 |
| `sniffio` | 1.3.1 | 已安装 |
| `tqdm` | 4.70.0 | 已安装 |
| `h11` | 0.16.0 | 已安装 |
| `exceptiongroup` | 1.3.1 | 已安装 |
| `distro` | — | 缺失；OpenAI SDK 声明需要 `>=1.7.0,<2` |
| `certifi` | — | 缺失；HTTPX/HTTPCore 声明需要 |
| `idna` | — | 缺失；HTTPX/AnyIO 声明需要 |

用 `/usr/local/bin/python3 -m pip install -r requirements-runtime.txt` 安装 OpenAI SDK 和当前缺少的基础依赖。`requirements-runtime.txt` 位于本目录；安装需要能访问 Python 包索引，或预先准备对应 wheel。已运行 `pip check`，发现上述三项缺失；因此当前环境虽然能 `import openai`，但不能视作 SDK 传输依赖完整。

## 自定义共享库

逐个文件的名称、版本、安装路径和版本来源另见 [ENVIRONMENT-LIBRARIES.csv](ENVIRONMENT-LIBRARIES.csv)。该 CSV 覆盖下方自定义目录中的 111 个共享库文件。能匹配到容器中同名 Debian 软件包的条目记录包版本；其余条目记录 SONAME/ABI 版本，并说明没有可确认的软件包版本。系统 `/lib`、`/usr/lib` 下其余基础共享库不属于此次识别出的自定义运行目录。

| 名称 | SONAME/版本 | 安装路径 |
|---|---:|---|
| `libstdc++.so.6` | 6 | `/opt/kamain-lib/libstdc++.so.6` |
| `libasan.so.6` | 6 | `/opt/workbench-runtime/libasan.so.6` |
| `libLLVM-14.so.1` | 14.1 | `/opt/clang14/lib/libLLVM-14.so.1` |
| `libclang-cpp.so.14` | 14 | `/opt/clang14/lib/libclang-cpp.so.14` |
| `libicudata.so.70`、`libicuuc.so.70` | 70 | `/opt/clang14/lib/` |
| `libap.so` | 未标版本 | `/media/iotteam/hd/pyh/mi/afl-proxy/proxy/build/libap.so` |
| `libapstage2.so` | 未标版本 | `/media/iotteam/hd/pyh/mi/afl-proxy/stage2/build/src/libapstage2.so` |

`/opt/qemu-libs/` 含 QEMU 运行时捆绑库。每个文件的安装路径均为该目录；下列 `.so.N` 中的 `N` 是 SONAME/ABI 号，并非精确软件包发行版本：

```text
libX11.so.6, libXau.so.6, libXcomposite.so.1, libXcursor.so.1,
libXdamage.so.1, libXdmcp.so.6, libXext.so.6, libXfixes.so.3,
libXi.so.6, libXinerama.so.1, libXrandr.so.2, libXrender.so.1,
libatk-1.0.so.0, libatk-bridge-2.0.so.0, libatspi.so.0, libblkid.so.1,
libbrotlicommon.so.1, libbrotlidec.so.1, libbsd.so.0, libbz2.so.1.0,
libcairo-gobject.so.2, libcairo.so.2, libcap.so.2, libcapstone.so.4,
libcom_err.so.2, libcrypto.so.3, libcurl.so.4, libdatrie.so.1,
libdbus-1.so.3, libepoxy.so.0, libexpat.so.1, libffi.so.8,
libfontconfig.so.1, libfreetype.so.6, libfribidi.so.0, libgcrypt.so.20,
libgdk-3.so.0, libgdk_pixbuf-2.0.so.0, libgio-2.0.so.0,
libglib-2.0.so.0, libgmodule-2.0.so.0, libgmp.so.10, libgnutls.so.30,
libgobject-2.0.so.0, libgpg-error.so.0, libgraphite2.so.3,
libgssapi_krb5.so.2, libgtk-3.so.0, libharfbuzz.so.0, libhogweed.so.6,
libibverbs.so.1, libidn2.so.0, libiscsi.so.7, libjpeg.so.8,
libk5crypto.so.3, libkeyutils.so.1, libkrb5.so.3, libkrb5support.so.0,
liblber-2.5.so.0, libldap-2.5.so.0, liblz4.so.1, liblzma.so.5,
libmd.so.0, libmount.so.1, libmysqlclient.so.21, libmysqlcppconn.so.7,
libncursesw.so.6, libnettle.so.8, libnghttp2.so.14, libnl-3.so.200,
libnl-route-3.so.200, libp11-kit.so.0, libpango-1.0.so.0,
libpangocairo-1.0.so.0, libpangoft2-1.0.so.0, libpcre.so.3,
libpcre2-8.so.0, libpixman-1.so.0, libpng16.so.16, libpsl.so.5,
librdmacm.so.1, librtmp.so.1, libsasl2.so.2, libselinux.so.1,
libssh.so.4, libssl.so.3, libsystemd.so.0, libtasn1.so.6,
libthai.so.0, libtinfo.so.6, libudev.so.1, libunistring.so.2,
libuuid.so.1, libwayland-client.so.0, libwayland-cursor.so.0,
libwayland-egl.so.1, libxcb-render.so.0, libxcb-shm.so.0,
libxcb.so.1, libxkbcommon.so.0, libz.so.1, libzstd.so.1
```

## 路径和版本说明

- `PATH_PREFIX=/usr/lib/llvm-15/bin` 是工作流传给分析任务的工具目录；它不是容器 shell 的 `PATH`。
- `LD_LIBRARY_PATH` 中出现的自定义库目录应与进程的加载需求对应。clang 14 的依赖目录 `/opt/clang14/lib` 当前没有被加入该变量。
- `/opt/qemu-libs` 中的库是单独捆绑文件夹；这些库未由其路径直接给出完整 Debian 包版本。当前仅从 SONAME 记录 ABI 版本，不猜测上游完整版本。
- 自定义构建的 SVF、Syzkaller 和 AFL proxy 可能没有标准版本输出；若需要严格重建环境，应另行锁定 Git commit、构建配置和二进制校验值。

