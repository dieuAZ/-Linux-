#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf '用法：%s <已完成的快照目录> [--push]\n' "$0" >&2
  exit 2
fi

stage_dir=$(realpath "$1")
mode=${2:-}
if [[ -n "$mode" && "$mode" != --push ]]; then
  printf '未知选项：%s\n' "$mode" >&2
  exit 2
fi

for part in workbench lx-codeql lx-db lx-query lx-ops lx-linux726; do
  if [[ ! -d "$stage_dir/$part" ]]; then
    printf '快照缺少目录：%s\n' "$stage_dir/$part" >&2
    exit 1
  fi
done

if [[ -f "$stage_dir/workbench/.dockerignore" ]] &&
   rg -q '^[[:space:]]*[^#[:space:]]' "$stage_dir/workbench/.dockerignore"; then
  printf '工作台快照的 .dockerignore 含排除规则，可能漏掉数据；请先移除规则。\n' >&2
  exit 1
fi
if [[ ! -f "$stage_dir/workbench/data/tasks.db" ]]; then
  printf '工作台快照缺少运行数据 tasks.db。\n' >&2
  exit 1
fi

exec 9>"$stage_dir/.build.lock"
if ! flock -n 9; then
  printf '同一快照目录已有镜像构建在运行。\n' >&2
  exit 1
fi

docker_root=$(docker info --format '{{.DockerRootDir}}')
available_kib=$(df -Pk "$docker_root" | awk 'NR == 2 { print $4 }')
minimum_kib=$((40 * 1024 * 1024))
if (( available_kib < minimum_kib )); then
  printf 'Docker 所在分区空闲不足 40 GiB（目前约 %s GiB）；未创建镜像。\n' \
    "$((available_kib / 1024 / 1024))" >&2
  exit 1
fi

script_dir=$(cd "$(dirname "$0")" && pwd)
container=${WORKBENCH_SOURCE_CONTAINER:-52143b958427}
snapshot_image=${WORKBENCH_SNAPSHOT_IMAGE:-syzkaller-workbench:ghcr-snapshot-20261022}
image=${WORKBENCH_IMAGE:-ghcr.io/dieuaz/chongmingniao:20261022}

top_output=$(docker top "$container" -eo pid,args) || {
  printf '无法读取容器进程，未创建镜像。\n' >&2
  exit 1
}
if printf '%s\n' "$top_output" | rg -q 'syz-manager|syz-fuzzer|qemu-system'; then
  printf '检测到正在运行的 Fuzz/QEMU 进程，拒绝制作快照。\n' >&2
  exit 1
fi

if [[ ${WORKBENCH_USE_EXISTING_SNAPSHOT:-0} == 1 ]]; then
  docker image inspect "$snapshot_image" >/dev/null
else
  docker commit --pause=true "$container" "$snapshot_image"
fi
docker buildx build --load --progress=plain \
  --file "$script_dir/Dockerfile.ghcr" \
  --build-arg "BASE_IMAGE=$snapshot_image" \
  --build-context "workbench=$stage_dir/workbench" \
  --build-context "lx-codeql=$stage_dir/lx-codeql" \
  --build-context "lx-db=$stage_dir/lx-db" \
  --build-context "lx-query=$stage_dir/lx-query" \
  --build-context "lx-ops=$stage_dir/lx-ops" \
  --build-context "lx-linux726=$stage_dir/lx-linux726" \
  --tag "$image" "$script_dir"

docker image inspect "$image" --format '已构建 {{.RepoTags}}，镜像 ID {{.Id}}'
if [[ "$mode" == --push ]]; then
  docker push "$image"
fi
