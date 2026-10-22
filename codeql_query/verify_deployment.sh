#!/usr/bin/env bash
set -euo pipefail
root=/media/iotteam/hd/lx/static-query-6.1
db=${DB:-/media/iotteam/hd/lx/static-query-testdb-6.1-simple-transfers}
results=/media/iotteam/hd/lx/ops/free-driven-staging/final-simple-transfer-results
bash /media/iotteam/hd/lx/ops/free-driven-staging/decode.sh "$db" "$results"
python3 "$root/tests/check_strict_baseline.py" "$results"
python3 "$root/tests/check_free_driven.py" "$results"
python3 "$root/tests/check_simple_transfers.py" "$results"
python3 "$root/dedup_concurrency_semantic_incidents.py" "$results" --output-dir /media/iotteam/hd/lx/ops/free-driven-staging/simple-transfer-semantic-results
