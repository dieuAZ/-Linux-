# syntax=docker/dockerfile:1.7
FROM python:3.10-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WORKBENCH_FUZZ_MODE=local \
    LLVM_LINK=/usr/bin/llvm-link-15 \
    SVF_ROOT=/media/iotteam/hd/pyh/mi/tools/SVF \
    SVF_BUILD=/media/iotteam/hd/pyh/mi/tools/SVF/Release-build \
    KAMAIN=/media/iotteam/hd/pyh/mi/ana/StateFuzz/sv-collector/build/lib/KAMain \
    PATH_PREFIX=/usr/lib/llvm-15/bin \
    LD_LIBRARY_PATH=/media/iotteam/hd/pyh/mi/afl-proxy/proxy/build:/media/iotteam/hd/pyh/mi/afl-proxy/stage2/build/src

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash bc binutils bison build-essential ca-certificates clang-15 cmake \
        dwarves flex git libdw-dev libelf-dev libncurses-dev libssl-dev \
        llvm-15 lld-15 ninja-build openssh-client patchelf pkg-config qemu-system-x86 \
        zstd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013

COPY --from=workbench . /media/iotteam/hd/html/syzkaller-workbench-realtime-dashboard-20261013/
COPY --from=mi-linux . /media/iotteam/hd/pyh/mi/linux-7.1.5/
COPY --from=mi-bitcode . /media/iotteam/hd/pyh/mi/analyse/lvout-linux/
COPY --from=mi-syzkaller . /media/iotteam/hd/pyh/mi/syzkaller/
COPY --from=mi-svf . /media/iotteam/hd/pyh/mi/tools/SVF/
COPY --from=mi-svf-build . /media/iotteam/hd/pyh/mi/tools/SVF/Release-build/
COPY --from=mi-collector run.sh map_access_sites.py /media/iotteam/hd/pyh/mi/ana/StateFuzz/sv-collector/
COPY --from=mi-collector build /media/iotteam/hd/pyh/mi/ana/StateFuzz/sv-collector/build/
COPY --from=mi-collector src /media/iotteam/hd/pyh/mi/ana/StateFuzz/sv-collector/src/
COPY --from=kamain-libstdcpp libstdc++.so.6 /opt/kamain-lib/libstdc++.so.6
COPY --from=mi-analyse . /media/iotteam/hd/pyh/mi/scripts/analyse/
COPY --from=mi-driver-fix . /media/iotteam/hd/pyh/mi/scripts/driver_fix/
COPY --from=mi-seed . /media/iotteam/hd/pyh/mi/scripts/seed_gener/
COPY --from=mi-probe . /media/iotteam/hd/pyh/mi/llm_probe/
COPY --from=mi-image bullseye.img bullseye.id_rsa bullseye.id_rsa.pub /media/iotteam/hd/pyh/mi/image/
COPY --from=mi-afl . /media/iotteam/hd/pyh/mi/afl-proxy/
COPY --from=mi-qemu . /media/iotteam/hd/pyh/mi/docker/fuzz6/runtime/qemu/
COPY --from=lx-codeql . /media/iotteam/hd/lx/codeql/
COPY --from=lx-db . /media/iotteam/hd/lx/codeql-db/
COPY --from=lx-query . /media/iotteam/hd/lx/static-query-6.1/
COPY --from=lx-ops . /media/iotteam/hd/lx/ops/ops-concurrency/

RUN patchelf --set-rpath /opt/kamain-lib "$KAMAIN" \
    && ldd -v "$KAMAIN" > /tmp/kamain-ldd.txt 2>&1 \
    && ! grep -q 'not found' /tmp/kamain-ldd.txt \
    && grep -q 'libstdc++.so.6 => /opt/kamain-lib/libstdc++.so.6' /tmp/kamain-ldd.txt \
    && rm /tmp/kamain-ldd.txt \
    && chmod +x start.sh \
    /media/iotteam/hd/pyh/mi/ana/StateFuzz/sv-collector/run.sh \
    /media/iotteam/hd/pyh/mi/syzkaller/bin/syz-manager \
    && python3 -m compileall -q .

EXPOSE 8080
ENTRYPOINT ["./start.sh"]
