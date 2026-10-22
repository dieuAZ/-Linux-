#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKBENCH_DIR=${WORKBENCH_DIR:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}
MI_ROOT=${MI_ROOT:-/media/iotteam/hd/pyh/mi}
LX_ROOT=${LX_ROOT:-/media/iotteam/hd/lx}
IMAGE=${IMAGE:-syzkaller-workbench:ready-kernel229-keyfix-20261021}
CONTAINER_NAME=${CONTAINER_NAME:-syzkaller-workbench}
DATA_DIR=${DATA_DIR:-$SCRIPT_DIR/data}
KVM_DEVICE=${KVM_DEVICE:-/dev/kvm}
REQUIRE_KVM=${REQUIRE_KVM:-1}
BUILD_IMAGE=${BUILD_IMAGE:-0}
BUILD_ONLY=${BUILD_ONLY:-0}
TMPFS_SIZE=${TMPFS_SIZE:-8g}
SHM_SIZE=${SHM_SIZE:-4g}
LIBSTDCXX_SOURCE=${LIBSTDCXX_SOURCE:-/usr/lib/x86_64-linux-gnu/libstdc++.so.6}

require_dir() {
    if [[ ! -d "$1" ]]; then
        echo "缺少目录：$1" >&2
        exit 1
    fi
}

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "缺少文件：$1" >&2
        exit 1
    fi
}

if [[ "$BUILD_IMAGE" == "1" ]]; then
    require_dir "$WORKBENCH_DIR"
    require_dir "$MI_ROOT"
    require_dir "$LX_ROOT"
    require_dir "$MI_ROOT/linux-7.1.5"
    require_dir "$MI_ROOT/analyse/lvout-linux"
    require_dir "$MI_ROOT/syzkaller"
    require_dir "$MI_ROOT/tools/SVF"
    require_dir "$MI_ROOT/tools/SVF/Release-build"
    require_dir "$MI_ROOT/ana/StateFuzz/sv-collector"
    require_dir "$MI_ROOT/ana/StateFuzz/sv-collector/build"
    require_dir "$MI_ROOT/scripts/analyse"
    require_dir "$MI_ROOT/scripts/driver_fix"
    require_dir "$MI_ROOT/scripts/seed_gener"
    require_dir "$MI_ROOT/llm_probe"
    require_dir "$MI_ROOT/afl-proxy"
    require_dir "$MI_ROOT/docker/fuzz6/runtime/qemu"
    require_dir "$LX_ROOT/codeql"
    require_dir "$LX_ROOT/codeql-db"
    require_dir "$LX_ROOT/static-query-6.1"
    require_dir "$LX_ROOT/ops/ops-concurrency"
    require_file "$MI_ROOT/image/bullseye.img"
    require_file "$MI_ROOT/image/bullseye.id_rsa"
    require_file "$MI_ROOT/linux-7.1.5/vmlinux"
    require_file "$MI_ROOT/linux-7.1.5/arch/x86/boot/bzImage"
    require_file "$LX_ROOT/codeql/codeql"
    require_file "$MI_ROOT/ana/StateFuzz/sv-collector/build/lib/KAMain"
    require_file "$LIBSTDCXX_SOURCE"
    if ! strings "$LIBSTDCXX_SOURCE" | grep -x 'GLIBCXX_3.4.32' > /dev/null; then
        echo "libstdc++ 缺少 GLIBCXX_3.4.32：$LIBSTDCXX_SOURCE" >&2
        exit 1
    fi
fi

if [[ "$BUILD_ONLY" != "1" && "$REQUIRE_KVM" == "1" && ! -e "$KVM_DEVICE" ]]; then
    echo "找不到 KVM 设备：$KVM_DEVICE；完整 Fuzz 运行需要它" >&2
    exit 1
fi

mkdir -p "$DATA_DIR"

if [[ "$BUILD_IMAGE" == "1" ]]; then
    libstdcpp_context=$(mktemp -d)
    trap 'rm -rf -- "$libstdcpp_context"' EXIT
    cp -L -- "$LIBSTDCXX_SOURCE" "$libstdcpp_context/libstdc++.so.6"
    docker buildx build \
        --load \
        --progress=plain \
        --tag "$IMAGE" \
        --file "$SCRIPT_DIR/Dockerfile" \
        --build-context workbench="$WORKBENCH_DIR" \
        --build-context mi-linux="$MI_ROOT/linux-7.1.5" \
        --build-context mi-bitcode="$MI_ROOT/analyse/lvout-linux" \
        --build-context mi-syzkaller="$MI_ROOT/syzkaller" \
        --build-context mi-svf="$MI_ROOT/tools/SVF" \
        --build-context mi-svf-build="$MI_ROOT/tools/SVF/Release-build" \
        --build-context mi-collector="$MI_ROOT/ana/StateFuzz/sv-collector" \
        --build-context kamain-libstdcpp="$libstdcpp_context" \
        --build-context mi-analyse="$MI_ROOT/scripts/analyse" \
        --build-context mi-driver-fix="$MI_ROOT/scripts/driver_fix" \
        --build-context mi-seed="$MI_ROOT/scripts/seed_gener" \
        --build-context mi-probe="$MI_ROOT/llm_probe" \
        --build-context mi-image="$MI_ROOT/image" \
        --build-context mi-afl="$MI_ROOT/afl-proxy" \
        --build-context mi-qemu="$MI_ROOT/docker/fuzz6/runtime/qemu" \
        --build-context lx-codeql="$LX_ROOT/codeql" \
        --build-context lx-db="$LX_ROOT/codeql-db" \
        --build-context lx-query="$LX_ROOT/static-query-6.1" \
        --build-context lx-ops="$LX_ROOT/ops/ops-concurrency" \
        "$SCRIPT_DIR"
    rm -rf -- "$libstdcpp_context"
    trap - EXIT
fi

if [[ "$BUILD_ONLY" == "1" ]]; then
    echo "镜像构建完成：$IMAGE"
    exit 0
fi

run_args=(
    run --rm
    --name "$CONTAINER_NAME"
    --network host
    --privileged
    --env WORKBENCH_FUZZ_MODE=local
    --env PYTHONUNBUFFERED=1
    --env HOME=/tmp/workbench-home
    --env XDG_CACHE_HOME=/tmp/workbench-home/.cache
    --env TMPDIR=/tmp
    --env LLM_API_BASE="${LLM_API_BASE:-https://api.deepseek.com}"
    --env LLM_MODEL="${LLM_MODEL:-deepseek-v4-pro}"
    --volume "$DATA_DIR:/media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013/data:rw"
    --tmpfs "/tmp:rw,nosuid,nodev,exec,size=$TMPFS_SIZE"
    --shm-size "$SHM_SIZE"
)

if [[ -n "${LLM_API_KEY:-}" ]]; then
    run_args+=(--env "LLM_API_KEY=$LLM_API_KEY")
fi
if [[ -e "$KVM_DEVICE" ]]; then
    run_args+=(--device "$KVM_DEVICE:$KVM_DEVICE")
fi

exec docker "${run_args[@]}" "$IMAGE"
