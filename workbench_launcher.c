#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHM_BYTES UINT64_C(4294967296)
#define DEFAULT_IMAGE "ghcr.io/dieuaz/chongmingniao:20261022"
#define DEFAULT_CONTAINER "syzkaller-workbench"
#define DEFAULT_APPDIR "/media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013"

static bool web_ready(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct timeval timeout = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(8080)};
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return false;
    }
    const char request[] = "HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    ssize_t sent = send(fd, request, sizeof(request) - 1, MSG_NOSIGNAL);
    char response[32] = "";
    ssize_t received = sent > 0 ? recv(fd, response, sizeof(response) - 1, 0) : -1;
    close(fd);
    return received >= 12 && strncmp(response, "HTTP/1.", 7) == 0 &&
           response[9] >= '2' && response[9] <= '3';
}

static bool wait_for_web(int seconds)
{
    for (int attempt = 0; attempt < seconds; ++attempt) {
        if (web_ready()) return true;
        sleep(1);
    }
    return web_ready();
}

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

#ifndef WORKBENCH_STOP_ONLY
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
#endif

static void usage(const char *program)
{
#ifdef WORKBENCH_STOP_ONLY
    fprintf(stderr, "用法：%s\n", program);
    fprintf(stderr, "停止工作台容器，不删除容器或数据。\n");
#else
    fprintf(stderr, "用法：%s [start | stop]\n", program);
    fprintf(stderr, "无参数或 start：已有容器则启动并检查网页服务；否则拉取镜像并创建，/dev/shm=4G。\n");
    fprintf(stderr, "stop：停止容器，不删除容器或数据。\n");
#endif
}

static int ensure_web_server(const char *docker, const char *container)
{
    if (wait_for_web(5)) {
        printf("工作台网页已就绪：http://127.0.0.1:8080\n");
        return 0;
    }
    fprintf(stderr, "网页服务未响应，尝试在容器 %s 中启动 server.py。\n", container);
    char *exec_args[] = {(char *)docker, "exec", "-d", "--workdir", DEFAULT_APPDIR,
                         (char *)container, "sh", "-c",
                         "exec python3 server.py >> /tmp/workbench-server.log 2>&1", NULL};
    if (docker_command(exec_args, NULL, 0, false) != 0) {
        fprintf(stderr, "无法启动网页服务，请检查容器中的 %s/server.py。\n", DEFAULT_APPDIR);
        return 1;
    }
    if (!wait_for_web(20)) {
        fprintf(stderr, "网页服务仍未响应，请检查容器日志及 /tmp/workbench-server.log。\n");
        return 1;
    }
    printf("工作台网页已就绪：http://127.0.0.1:8080\n");
    return 0;
}

static int create_container(const char *docker, const char *container,
                            const char *image)
{
    char *image_check[] = {(char *)docker, "image", "inspect", (char *)image,
                           "--format", "{{.Id}}", NULL};
    char image_id[128];
    if (docker_command(image_check, image_id, sizeof(image_id), true) != 0) {
        const char *archive = getenv("WORKBENCH_IMAGE_ARCHIVE");
        char *pull_args[] = {(char *)docker, "pull", (char *)image, NULL};
        char *load_args[] = {(char *)docker, "load", "--input", (char *)archive, NULL};
        int result = archive && access(archive, R_OK) == 0
                     ? docker_command(load_args, NULL, 0, false)
                     : docker_command(pull_args, NULL, 0, false);
        if (result != 0 ||
            docker_command(image_check, image_id, sizeof(image_id), true) != 0) {
            fprintf(stderr, "无法获取镜像：%s\n", image);
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
                       "--format", "{{.State.Running}} {{.HostConfig.ShmSize}} {{.Config.Image}}", NULL};
    char state[768] = "";
    int inspect_result = docker_command(inspect, state, sizeof(state), true);
    bool exists = inspect_result == 0;
    bool running = false;
    unsigned long long shm = 0;
    char running_word[6], existing_image[512];
    if (exists && sscanf(state, "%5s %llu %511s", running_word, &shm, existing_image) != 3) {
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

    if (exists && strcmp(existing_image, image) != 0)
        fprintf(stderr, "复用已有容器 %s（镜像 %s）；不会替换或清除其数据。\n",
                container, existing_image);
    if (exists && shm != SHM_BYTES) {
        fprintf(stderr, "警告：已有容器 %s 的 /dev/shm 为 %llu 字节，不是 4G；不会自动替换。\n",
                container, shm);
    }
    if (!running) {
        if (!exists && create_container(docker, container, image) != 0) return 1;
        char *start_args[] = {(char *)docker, "start", (char *)container, NULL};
        if (docker_command(start_args, NULL, 0, false) != 0) return 1;
    } else {
        printf("容器 %s 已在运行。\n", container);
    }
    return ensure_web_server(docker, container);
}

int main(int argc, char **argv)
{
#ifdef WORKBENCH_STOP_ONLY
    if (argc == 1) return manage_container(false);
    usage(argv[0]);
    return argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) ? 0 : 2;
#else
    if (argc == 1 && access("/.dockerenv", F_OK) == 0) return container_entry();
    if (argc == 1) return manage_container(true);
    if (argc == 2 && strcmp(argv[1], "start") == 0) return manage_container(true);
    if (argc == 2 && strcmp(argv[1], "stop") == 0) return manage_container(false);
    usage(argv[0]);
    return argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) ? 0 : 2;
#endif
}
