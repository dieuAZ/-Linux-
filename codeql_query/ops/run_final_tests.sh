#!/usr/bin/env bash
set -euo pipefail
root=/media/iotteam/hd/lx/static-query-6.1
codeql=/media/iotteam/hd/lx/codeql/codeql
db=${DB:-/media/iotteam/hd/lx/static-query-testdb-6.1-ops-final}
results=${RESULTS:-/media/iotteam/hd/lx/ops}
cd "$root"
for query in OpsConcurrentFreeUsePaths OpsObjectTransferEvidence; do
  "$codeql" query run --database="$db" --output="$results/$query.bqrs" \
    --threads=4 --ram=10000 "ops/$query.ql"
  "$codeql" bqrs decode --format=csv --output="$results/$query.csv" "$results/$query.bqrs"
done
python3 ops/verify_object_candidates.py "$results/OpsConcurrentFreeUsePaths.csv"
python3 ops/verify_object_transfers.py "$results/OpsConcurrentFreeUsePaths.csv" "$results/OpsObjectTransferEvidence.csv"
python3 ops/verify_ops_callbacks.py "$results/OpsConcurrentFreeUsePaths.csv"
python3 ops/verify_ops_final.py "$results/OpsConcurrentFreeUsePaths.csv"
