# 崇明鸟

大模型辅助的 Linux 内核全驱动漏洞挖掘系统。代码仓库：<https://github.com/dieuAZ/-Linux->。

## 运行环境

仅支持 **Linux 宿主机**。需要安装并启动 Docker，当前用户须有执行 Docker 命令的权限。`start.exe` 和 `stop.exe` 是 Linux ELF 可执行文件，文件名中的 `.exe` 不代表 Windows 程序。运行 Fuzz 时还需要宿主机提供 `/dev/kvm`。

## 启动与关闭

在包含这两个文件的目录运行：

```bash
./start.exe
./stop.exe
```

`start.exe` 会优先启动已有的 `syzkaller-workbench` 容器，并确保网页服务可访问；没有容器时，使用本地镜像创建容器；本地也没有镜像时，自动从 `ghcr.io/dieuaz/chongmingniao:20261022` 拉取。新容器的 `/dev/shm` 为 4G。若镜像尚未设为公开，请先运行 `docker login ghcr.io`。

启动后，在宿主机浏览器打开 <http://127.0.0.1:8080>。`stop.exe` 只停止容器，不删除容器或运行数据。已有容器会被复用，不会被自动替换；已有容器的 `/dev/shm` 无法原地调整。
