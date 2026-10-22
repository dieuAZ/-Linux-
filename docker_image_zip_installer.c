#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_for(pid_t pid)
{
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) { perror("waitpid"); return 1; }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static void close_input(void)
{
    FILE *null_file = fopen("/dev/null", "r");
    if (!null_file || dup2(fileno(null_file), STDIN_FILENO) < 0) _exit(127);
    fclose(null_file);
}

static int run(char *const argv[], bool quiet_stdout)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        close_input();
        if (quiet_stdout) {
            FILE *null_file = fopen("/dev/null", "w");
            if (!null_file || dup2(fileno(null_file), STDOUT_FILENO) < 0) _exit(127);
            fclose(null_file);
        }
        execvp(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }
    return wait_for(pid);
}

static bool ends_with(const char *name, const char *suffix)
{
    size_t n = strlen(name), s = strlen(suffix);
    return n >= s && strcasecmp(name + n - s, suffix) == 0;
}

static bool is_image_archive(const char *name)
{
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;
    return *base && (ends_with(base, ".tar") || ends_with(base, ".tar.gz") ||
                     ends_with(base, ".tgz") || ends_with(base, ".tar.bz2") ||
                     ends_with(base, ".tar.xz") || ends_with(base, ".tar.zst"));
}

/* unzip treats member names as patterns; reject metacharacters rather than
 * accidentally selecting more than one ZIP entry. Nothing is extracted to disk. */
static bool safe_member(const char *name)
{
    if (!*name || *name == '/' || strstr(name, "../") ||
        strpbrk(name, "*?[]\\\r\n")) return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p)
        if (*p < 32 || *p == 127) return false;
    return true;
}

static int choose_member(const char *zip_path, const char *requested, char **selected)
{
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); return 1; }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(fds[0]); close(fds[1]); return 1; }
    if (pid == 0) {
        close_input();
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
        execlp("unzip", "unzip", "-Z1", zip_path, (char *)NULL);
        perror("unzip");
        _exit(127);
    }
    close(fds[1]);
    FILE *stream = fdopen(fds[0], "r");
    if (!stream) { perror("fdopen"); close(fds[0]); wait_for(pid); return 1; }
    char *line = NULL;
    size_t cap = 0, matches = 0;
    while (getline(&line, &cap, stream) >= 0) {
        size_t length = strlen(line);
        if (length && line[length - 1] == '\n') line[--length] = '\0';
        if (length && line[length - 1] == '\r') line[--length] = '\0';
        if (!safe_member(line) || !is_image_archive(line)) continue;
        if (requested && strcmp(requested, line) != 0) continue;
        ++matches;
        if (matches == 1) {
            *selected = strdup(line);
            if (!*selected) { perror("strdup"); break; }
        }
        if (!requested) fprintf(stderr, "  %s\n", line);
    }
    free(line);
    int read_error = ferror(stream);
    fclose(stream);
    int status = wait_for(pid);
    if (status || read_error || (matches && !*selected)) {
        fprintf(stderr, "无法读取 ZIP 文件目录。\n");
        return 1;
    }
    if (matches == 0) {
        fprintf(stderr, "ZIP 中没有%s Docker 镜像归档（.tar/.tar.gz/.tgz 等）。\n",
                requested ? "指定的" : "可用的");
        return 1;
    }
    if (matches != 1) {
        fprintf(stderr, "找到多个镜像归档，请用 --entry 指定其中一个。\n");
        return 1;
    }
    return 0;
}

static int load_image(const char *zip_path, const char *member, const char *docker)
{
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); return 1; }
    pid_t unzip_pid = fork();
    if (unzip_pid < 0) { perror("fork"); close(fds[0]); close(fds[1]); return 1; }
    if (unzip_pid == 0) {
        close_input();
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
        execlp("unzip", "unzip", "-p", zip_path, member, (char *)NULL);
        perror("unzip");
        _exit(127);
    }
    pid_t docker_pid = fork();
    if (docker_pid < 0) {
        perror("fork"); close(fds[0]); close(fds[1]); wait_for(unzip_pid); return 1;
    }
    if (docker_pid == 0) {
        close(fds[1]);
        if (dup2(fds[0], STDIN_FILENO) < 0) _exit(127);
        close(fds[0]);
        execlp(docker, docker, "image", "load", (char *)NULL);
        perror(docker);
        _exit(127);
    }
    close(fds[0]); close(fds[1]);
    int unzip_status = wait_for(unzip_pid);
    int docker_status = wait_for(docker_pid);
    if (unzip_status || docker_status) {
        fprintf(stderr, "镜像导入失败：ZIP 解压状态=%d，Docker 加载状态=%d。\n",
                unzip_status, docker_status);
        return 1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr, "用法：%s <docker镜像.zip> [--entry ZIP内的镜像归档路径]\n", program);
    fprintf(stderr, "ZIP 须包含 docker save 导出的 .tar 或受支持的压缩 tar；不会解压到磁盘。\n");
    fprintf(stderr, "多个归档时使用 --entry 指定一个；本程序只导入镜像，不启动容器。\n");
}

int main(int argc, char **argv)
{
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        usage(argv[0]);
        return 0;
    }
    if (argc != 2 && !(argc == 4 && !strcmp(argv[2], "--entry"))) {
        usage(argv[0]);
        return 2;
    }
    const char *requested = argc == 4 ? argv[3] : NULL;
    if (requested && (!safe_member(requested) || !is_image_archive(requested))) {
        fprintf(stderr, "无效的 ZIP 内文件名。\n");
        return 2;
    }
    char *zip_path = realpath(argv[1], NULL);
    struct stat info;
    if (!zip_path || stat(zip_path, &info) != 0 || !S_ISREG(info.st_mode)) {
        fprintf(stderr, "ZIP 文件不存在或不是普通文件：%s\n", argv[1]);
        free(zip_path);
        return 1;
    }
    FILE *zip_file = fopen(zip_path, "rb");
    unsigned char magic[4];
    if (!zip_file || fread(magic, 1, sizeof(magic), zip_file) != sizeof(magic) ||
        memcmp(magic, "PK\003\004", sizeof(magic)) != 0) {
        fprintf(stderr, "文件不是可识别的非空 ZIP：%s\n", zip_path);
        if (zip_file) fclose(zip_file);
        free(zip_path);
        return 1;
    }
    fclose(zip_file);
    char *member = NULL;
    if (!requested) fprintf(stderr, "ZIP 内找到的镜像归档：\n");
    if (choose_member(zip_path, requested, &member)) {
        free(member); free(zip_path);
        return 1;
    }
    const char *docker = getenv("WORKBENCH_DOCKER_BIN");
    if (!docker || !*docker) docker = "docker";
    char *info_args[] = {(char *)docker, "info", "--format", "{{.ServerVersion}}", NULL};
    if (run(info_args, true)) {
        fprintf(stderr, "Docker 不可用；请检查服务和当前用户权限。\n");
        free(member); free(zip_path);
        return 1;
    }
    fprintf(stderr, "正在校验 ZIP 中的 %s（大镜像可能需要一些时间）...\n", member);
    char *test_args[] = {"unzip", "-tq", zip_path, member, NULL};
    if (run(test_args, true)) {
        fprintf(stderr, "ZIP 镜像归档校验失败，未执行 docker image load。\n");
        free(member); free(zip_path);
        return 1;
    }
    fprintf(stderr, "正在导入 Docker 镜像：%s\n", member);
    int result = load_image(zip_path, member, docker);
    if (!result) fprintf(stderr, "导入完成；可执行 ./start.exe start 启动容器。\n");
    free(member); free(zip_path);
    return result;
}
