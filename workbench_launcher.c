#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHM_BYTES UINT64_C(4294967296)
#define DEFAULT_IMAGE "syzkaller-workbench:ready-kernel229-lvout715-shmfix-20261021"
#define DEFAULT_CONTAINER "syzkaller-workbench"
#define DEFAULT_LX_ROOT "/media/iotteam/hd/lx"

static const char *setting(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value && *value ? value : fallback;
}

static int docker_command(char *const args[], char *output, size_t output_size,
                          bool quiet_stderr)
{
    int fds[2] = {-1, -1};
    if (output && pipe(fds) != 0) {
        perror("pipe");
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        if (output) { close(fds[0]); close(fds[1]); }
        return -1;
    }
    if (child == 0) {
        if (output) {
            close(fds[0]);
            if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
            close(fds[1]);
        }
        if (quiet_stderr) {
            FILE *null_file = fopen("/dev/null", "w");
            if (null_file) {
                if (dup2(fileno(null_file), STDERR_FILENO) < 0) _exit(127);
                fclose(null_file);
            }
        }
        execvp(args[0], args);
        perror(args[0]);
        _exit(127);
    }
    if (output) {
        close(fds[1]);
        size_t used = 0;
        while (used + 1 < output_size) {
            ssize_t count = read(fds[0], output + used, output_size - used - 1);
            if (count > 0) used += (size_t)count;
            else if (count == 0) break;
            else if (errno != EINTR) break;
        }
        output[used] = '\0';
        close(fds[0]);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) { perror("waitpid"); return -1; }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int workbench_dir(char *directory, size_t size)
{
    ssize_t length = readlink("/proc/self/exe", directory, size - 1);
    if (length < 0 || (size_t)length >= size - 1) return -1;
    directory[length] = '\0';
    char *slash = strrchr(directory, '/');
    if (!slash) return -1;
    *slash = '\0';
    return 0;
}

static int container_entry(void)
{
    char directory[PATH_MAX];
    if (workbench_dir(directory, sizeof(directory)) != 0 || chdir(directory) != 0) {
        perror("workbench directory");
        return 1;
    }
    /* Keep the old start.sh behavior for images whose entrypoint is ./start.sh. */
    if (mount(NULL, "/tmp", NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL) != 0) {
        perror("remount /tmp with exec");
        return 1;
    }
    execlp("python3", "python3", "server.py", (char *)NULL);
    perror("python3 server.py");
    return 1;
}

static void usage(const char *program)
{
    fprintf(stderr, "用法：%s [start | stop]\n", program);
    fprintf(stderr, "无参数运行时显示开启/关闭菜单。\n");
    fprintf(stderr, "start：已有容器则启动；否则从本地镜像创建，/dev/shm=4G。\n");
    fprintf(stderr, "stop：停止容器，不删除容器或数据。\n");
}

static int create_container(const char *docker, const char *container,
                            const char *image)
{
    char directory[PATH_MAX], data_dir[PATH_MAX];
    char app_mount[PATH_MAX * 2 + 8], data_mount[PATH_MAX * 2 + 8];
    char lx_mount[PATH_MAX * 2 + 8];
    const char *lx_root = setting("WORKBENCH_LX_ROOT", DEFAULT_LX_ROOT);
    const char *data_override = getenv("WORKBENCH_DATA_DIR");
    struct stat info;
    if (workbench_dir(directory, sizeof(directory)) != 0) {
        fprintf(stderr, "无法确定程序所在目录\n");
        return 1;
    }
    if (data_override && *data_override) {
        if (snprintf(data_dir, sizeof(data_dir), "%s", data_override) >= (int)sizeof(data_dir)) return 1;
    } else if (snprintf(data_dir, sizeof(data_dir), "%s/docker_query/data", directory) >= (int)sizeof(data_dir)) {
        return 1;
    }
    if (data_dir[0] != '/' || lx_root[0] != '/' ||
        stat(data_dir, &info) != 0 || !S_ISDIR(info.st_mode) ||
        stat(lx_root, &info) != 0 || !S_ISDIR(info.st_mode)) {
        fprintf(stderr, "数据目录或 LX 目录不存在：%s, %s\n", data_dir, lx_root);
        return 1;
    }
    if (snprintf(app_mount, sizeof(app_mount), "%s:%s:rw", directory, directory) >= (int)sizeof(app_mount) ||
        snprintf(data_mount, sizeof(data_mount), "%s:%s/data:rw", data_dir, directory) >= (int)sizeof(data_mount) ||
        snprintf(lx_mount, sizeof(lx_mount), "%s:%s:rw", lx_root, DEFAULT_LX_ROOT) >= (int)sizeof(lx_mount)) {
        fprintf(stderr, "挂载路径过长\n");
        return 1;
    }

    char *image_check[] = {(char *)docker, "image", "inspect", (char *)image,
                           "--format", "{{.Id}}", NULL};
    char image_id[128];
    if (docker_command(image_check, image_id, sizeof(image_id), true) != 0) {
        const char *archive = getenv("WORKBENCH_IMAGE_ARCHIVE");
        if (!archive || access(archive, R_OK) != 0) {
            fprintf(stderr, "本地镜像不存在：%s。可设置 WORKBENCH_IMAGE_ARCHIVE 指向 docker save 镜像包。\n", image);
            return 1;
        }
        char *load_args[] = {(char *)docker, "load", "--input", (char *)archive, NULL};
        if (docker_command(load_args, NULL, 0, false) != 0 ||
            docker_command(image_check, image_id, sizeof(image_id), true) != 0) {
            fprintf(stderr, "镜像包加载后仍找不到指定镜像：%s\n", image);
            return 1;
        }
    }

    char *args[64];
    size_t i = 0;
#define ADD(value) do { args[i++] = (char *)(value); } while (0)
    ADD(docker); ADD("create"); ADD("--name"); ADD(container);
    ADD("--network"); ADD("host"); ADD("--privileged");
    ADD("--shm-size"); ADD("4g");
    ADD("--tmpfs"); ADD("/tmp:rw,nosuid,nodev,exec,size=8g");
    ADD("--env"); ADD("WORKBENCH_FUZZ_MODE=local");
    ADD("--env"); ADD("PYTHONUNBUFFERED=1");
    ADD("--env"); ADD("HOME=/tmp/workbench-home");
    ADD("--env"); ADD("XDG_CACHE_HOME=/tmp/workbench-home/.cache");
    ADD("--env"); ADD("TMPDIR=/tmp");
    ADD("--volume"); ADD(app_mount);
    ADD("--volume"); ADD(data_mount);
    ADD("--volume"); ADD(lx_mount);
    if (access("/dev/kvm", F_OK) == 0) {
        ADD("--device"); ADD("/dev/kvm:/dev/kvm");
    } else if (strcmp(setting("WORKBENCH_REQUIRE_KVM", "1"), "0") != 0) {
        fprintf(stderr, "找不到 /dev/kvm；如只运行非 Fuzz 阶段，可设置 WORKBENCH_REQUIRE_KVM=0。\n");
        return 1;
    }
    if (getenv("LLM_API_KEY")) { ADD("--env"); ADD("LLM_API_KEY"); }
    if (getenv("LLM_API_BASE")) { ADD("--env"); ADD("LLM_API_BASE"); }
    if (getenv("LLM_MODEL")) { ADD("--env"); ADD("LLM_MODEL"); }
    ADD(image); args[i] = NULL;
#undef ADD
    if (docker_command(args, NULL, 0, false) != 0) {
        fprintf(stderr, "创建容器失败，未删除任何现有容器。\n");
        return 1;
    }
    return 0;
}

static int manage_container(bool start)
{
    const char *docker = setting("WORKBENCH_DOCKER_BIN", "docker");
    const char *container = setting("WORKBENCH_CONTAINER_NAME", DEFAULT_CONTAINER);
    const char *image = setting("WORKBENCH_IMAGE", DEFAULT_IMAGE);
    char *info[] = {(char *)docker, "info", "--format", "{{.ServerVersion}}", NULL};
    char docker_version[128];
    if (docker_command(info, docker_version, sizeof(docker_version), false) != 0) {
        fprintf(stderr, "Docker 不可用；请检查 Docker 服务与当前用户权限。\n");
        return 1;
    }
    char *inspect[] = {(char *)docker, "container", "inspect", (char *)container,
                       "--format", "{{.State.Running}} {{.HostConfig.ShmSize}}", NULL};
    char state[128] = "";
    int inspect_result = docker_command(inspect, state, sizeof(state), true);
    bool exists = inspect_result == 0;
    bool running = false;
    unsigned long long shm = 0;
    char running_word[6];
    if (exists && sscanf(state, "%5s %llu", running_word, &shm) != 2) {
        fprintf(stderr, "无法解析容器状态：%s\n", state);
        return 1;
    }
    if (exists) running = strcmp(running_word, "true") == 0;

    if (!start) {
        if (!exists) { printf("容器 %s 尚未创建。\n", container); return 0; }
        if (!running) { printf("容器 %s 已停止。\n", container); return 0; }
        char *stop_args[] = {(char *)docker, "stop", "--time", "30", (char *)container, NULL};
        return docker_command(stop_args, NULL, 0, false) == 0 ? 0 : 1;
    }

    if (exists && shm != SHM_BYTES) {
        fprintf(stderr, "现有容器 %s 的 /dev/shm 为 %llu 字节，不是 4G。\n", container, shm);
        fprintf(stderr, "Docker 无法原地修改；当前容器不会被自动停止或删除。\n");
        fprintf(stderr, "注意：未挂载到宿主机的历史分析产物不会自动进入新容器，请先迁移或备份。\n");
        fprintf(stderr, "确认数据后，可停止并将旧容器改名保留，再运行 start 创建新容器：\n");
        fprintf(stderr, "命令：%s stop\n", "./start.sh");
        fprintf(stderr, "      docker rename %s %s-before-shm4g\n", container, container);
        fprintf(stderr, "      %s start\n", "./start.sh");
        return 1;
    }
    if (running) { printf("容器 %s 已在运行，/dev/shm=4G。\n", container); return 0; }
    if (!exists && create_container(docker, container, image) != 0) return 1;
    char *start_args[] = {(char *)docker, "start", (char *)container, NULL};
    if (docker_command(start_args, NULL, 0, false) != 0) return 1;
    printf("工作台已启动：http://127.0.0.1:8080 （/dev/shm=4G）\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1 && access("/.dockerenv", F_OK) == 0) return container_entry();
    if (argc == 1) {
        char choice[16];
        printf("1. 开启容器\n2. 关闭容器\n请选择 [1/2]：");
        fflush(stdout);
        if (!fgets(choice, sizeof(choice), stdin)) return 2;
        if (strcmp(choice, "1\n") == 0 || strcmp(choice, "1") == 0) return manage_container(true);
        if (strcmp(choice, "2\n") == 0 || strcmp(choice, "2") == 0) return manage_container(false);
        fprintf(stderr, "无效选项。\n");
        return 2;
    }
    if (argc == 2 && strcmp(argv[1], "start") == 0) return manage_container(true);
    if (argc == 2 && strcmp(argv[1], "stop") == 0) return manage_container(false);
    usage(argv[0]);
    return argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) ? 0 : 2;
}
