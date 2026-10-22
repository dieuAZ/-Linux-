#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE_IMAGE=${BASE_IMAGE:-syzkaller-workbench:standalone-20261021}
IMAGE=${IMAGE:-syzkaller-workbench:portable-20261021}
LIBSTDCXX_SOURCE=${LIBSTDCXX_SOURCE:-/usr/lib/x86_64-linux-gnu/libstdc++.so.6}
LIBASAN_SOURCE=${LIBASAN_SOURCE:-/usr/lib/x86_64-linux-gnu/libasan.so.6}
QEMU_SOURCE=${QEMU_SOURCE:-/media/iotteam/hd/pyh/mi/docker/fuzz6/runtime/qemu/qemu-system-x86_64}
GCC11_ROOT=${GCC11_ROOT:-/usr/lib/gcc/x86_64-linux-gnu/11}

if [[ ! -f "$LIBSTDCXX_SOURCE" ]]; then
    echo "缺少 libstdc++：$LIBSTDCXX_SOURCE" >&2
    exit 1
fi
if ! strings "$LIBSTDCXX_SOURCE" | grep -x 'GLIBCXX_3.4.32' > /dev/null; then
    echo "libstdc++ 缺少 GLIBCXX_3.4.32：$LIBSTDCXX_SOURCE" >&2
    exit 1
fi
if [[ ! -f "$LIBASAN_SOURCE" || ! -x "$QEMU_SOURCE" ]]; then
    echo "缺少宿主机的 libasan.so.6 或项目 QEMU" >&2
    exit 1
fi
if [[ ! -x "$GCC11_ROOT/cc1" || ! -f "$GCC11_ROOT/include/stddef.h" ]]; then
    echo "缺少宿主机 GCC 11 工具链：$GCC11_ROOT" >&2
    exit 1
fi
docker image inspect "$BASE_IMAGE" > /dev/null

build_context=$(mktemp -d)
trap 'rm -rf -- "$build_context"' EXIT
cp -L -- "$LIBSTDCXX_SOURCE" "$build_context/libstdc++.so.6"
cp -- "$SCRIPT_DIR/../server.py" "$build_context/server.py"
cp -L -- "$LIBASAN_SOURCE" "$build_context/libasan.so.6"
cp -- "$SCRIPT_DIR/qemu-wrapper" "$build_context/qemu-wrapper"
mkdir "$build_context/qemu-libs"
mkdir -p "$build_context/gcc11/lib" "$build_context/gcc11/include" \
    "$build_context/gcc11/include-arch" "$build_context/gcc11/bin"
tar -C "$GCC11_ROOT" --dereference --exclude='./32' --exclude='./x32' -cf - . \
    | tar -C "$build_context/gcc11/lib" -xf -
cp -a /usr/include/c++/11/. "$build_context/gcc11/include/"
cp -a /usr/include/x86_64-linux-gnu/c++/11/. "$build_context/gcc11/include-arch/"
cp -L /usr/bin/x86_64-linux-gnu-gcc-11 "$build_context/gcc11/bin/gcc-11"
cp -L /usr/bin/x86_64-linux-gnu-g++-11 "$build_context/gcc11/bin/g++-11"
cp -L /usr/bin/x86_64-linux-gnu-cpp-11 "$build_context/gcc11/bin/cpp-11"
python3 "$SCRIPT_DIR/stage-openai-python.py" "$build_context/python-site"
ldd "$QEMU_SOURCE" | awk '$2=="=>" && $3 ~ /^\// {print $1, $3}' | while read -r name path; do
    case "$name" in
        libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libresolv.so.2|libgcc_s.so.1|libstdc++.so.6) continue ;;
    esac
    cp -L -- "$path" "$build_context/qemu-libs/$name"
done
docker buildx build --load --network=none --progress=plain \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --file "$SCRIPT_DIR/Dockerfile.offline-runtime" \
    --tag "$IMAGE" "$build_context"

docker run --rm --network none --entrypoint /bin/sh "$IMAGE" -c '
    test -x "$KAMAIN"
    ldd -v "$KAMAIN" > /tmp/kamain-ldd.txt 2>&1
    ! grep -q "not found" /tmp/kamain-ldd.txt
    grep -q "GLIBCXX_3.4.32) => /opt/kamain-lib/libstdc++.so.6" /tmp/kamain-ldd.txt
    ldd /media/iotteam/hd/pyh/mi/syzkaller/bin/syz-manager > /tmp/syz-ldd.txt 2>&1
    ! grep -q "not found" /tmp/syz-ldd.txt
    /media/iotteam/hd/pyh/mi/docker/fuzz6/runtime/qemu/qemu-system-x86_64 --version
    test "$(gcc -dumpfullversion)" = 11.4.0
    test "$(g++ -dumpfullversion)" = 11.4.0
    python3 -c "from openai import OpenAI; print(OpenAI.__name__)"
'
echo "独立镜像构建并验证完成：$IMAGE"
