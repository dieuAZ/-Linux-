# Ops object-related concurrency candidates

Run OpsConcurrentFreeUsePaths.ql as the primary candidate query. It joins a
concrete ops aggregate binding, free/use callback implementations, actual dispatch
sites, and common pointer or modeled storage/recovery evidence. Multiple ops
tables remain separate even when they share an interface type or implementation.
Methods may pair with themselves. An explicit asynchronous startup API is not
required; overlap must be reviewed using the calling framework.

OpsObjectFlow.qll tracks callback arguments and ops receivers independently.
OpsObjectTransfers.qll covers fields, private setter/getter pairs and container
recovery. OpsValueSummaries.qll handles pointer returns and getter wrappers with
call-site argument/result pairing. OpsCallbackObjects.qll follows callback
parameters through aliases, fields, getters, recovery and helper calls to free/use.

Results contain the concrete ops binding, method names, free/use and dispatch
locations, object origins, propagation traces and callback depths. These are
candidate associations, not proof of overlapping executions or a UAF. Common
storage does not establish overwrite ordering. Analysis is bounded (up to five
callback steps and two getter/return wrapper summary edges); opaque indirect
helpers and arbitrary heap structures are not fully covered.

OpsBindings.ql, OpsDispatch.ql, OpsFreeEvents.ql and OpsUseEvents.ql are diagnostic
queries. OpsUnresolvedObjects.ql is separate and must not be merged into primary
candidates. OpsObjectTransferEvidence.ql exposes modeled storage/recovery evidence.

Validated fixture: tests/ops_final_test.c.
Database: /media/iotteam/hd/lx/static-query-testdb-6.1-ops-final.
Regression command: bash ops/run_final_tests.sh.
Primary CSV: /media/iotteam/hd/lx/ops/OpsConcurrentFreeUsePaths.csv.
The LLM API remains unconfigured; no model calls are made by these queries/tests.
