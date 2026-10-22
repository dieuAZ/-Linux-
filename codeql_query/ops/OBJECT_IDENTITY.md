# Runtime object candidate evidence

Run OpsConcurrentFreeUsePaths.ql for evidence-backed candidates and
OpsUnresolvedObjects.ql for dispatch pairs lacking supported identity evidence.
Neither query establishes concurrency or a vulnerability.

OpsObjectFlow.qll uses CodeQL local pointer-value flow and propagates actual
arguments into parameters of direct wrapper calls, retaining the common caller
origin. Propagation is limited to five direct-call edges per branch. Each
candidate requires one pointer origin reaching both callback dispatch arguments,
both dispatch receivers, and an assignment of the concrete ops table to that
origin object. Callback parameter positions are mapped independently.

Output includes runtime_object_key, object_evidence_kind, dispatch locations,
argument traces and wrapper depths. Paths are context only and do not filter
sibling fields. Arbitrary ops method names are accepted. Reading a free API's
argument expression is excluded as a standalone use.

Evidence means may_same_runtime_object. A shared parameter can denote different
objects across separate invocations; an allocation site can execute repeatedly.
These are static value-flow witnesses, not runtime address equality guarantees.
Missing evidence never establishes disjointness: distinct pointer parameters can
alias. Unresolved dispatch pairs are kept in the second query for review.

Current limits include global publication, indirect
wrappers, returned pointer flows, and callbacks whose
free/use root is hidden behind an unmodeled helper. Binding evidence currently
recognizes field assignments of &table; other initialization forms need models.
OpsUnresolvedObjects does not resolve concrete binding per dispatch and can
therefore include several possible tables of the same interface type.

## Bounded transfer extensions

OpsObjectTransfers.qll adds at most two pointer-value transfer edges per local
flow segment (the budget resets across each of the five direct wrapper edges). Reads are
limited to ops dispatch functions and up to five direct wrapper edges. Host
identity uses a common ordinary pointer source (up to three direct call edges),
with at most two matching host field components. Field equality uses the actual
CodeQL Field entity, not a field name alone. Stores and loads are may-alias
witnesses: no overwrite ordering or lock/lifetime claim is made.

Supported transfers:
- Pointer field store/load, including file->private_data and nested host fields.
- Matching dev, platform, pci, usb-interface, i2c-client and spi private-data
  setter/getter pairs, with a common host witness.
- container_of/container_of_const recovery from an address of an embedded class
  member. The member Field, declaring type, and value flow into the expanded
  macro must match. Pointer members are excluded. This does not identify arbitrary
  custom macros, union syntax, nested member designators or an unobserved member
  pointer publication path.

API families are matched within their own pair; cross-family aliasing (for example
platform_set_drvdata followed by dev_get_drvdata) is not inferred automatically.
OpsCallbackObjects.qll now tracks callback parameters into private fields,
modeled getters, container_of recovery and direct helper parameters, up to five
combined transitions. Receiver identity and callback argument identity are tracked
separately, allowing methods to receive a member pointer from their receiver.
No explicit workqueue/thread/timer startup is required by the ops candidate query.
The concrete ops binding is the central grouping key; overlap is left for framework
and locking review. Storage/getter paths are context, not pointee lifetime proofs.

Candidate argument traces now include transfer evidence, including wrapper-spanning
recovery when the final local transfer enters dispatch.
OpsObjectTransferEvidence.ql exports source keys, dispatch locations and transfer
descriptions. Join these on runtime_object_key and dispatch location with the
candidate CSV. Wrapper-spanning recovery is also reflected in candidate presence;
the evidence query itself reports only transfers ending in a local dispatch.

Regression database for this extension:
/media/iotteam/hd/lx/static-query-testdb-6.1-ops-transfers-v2
Full-kernel performance has not yet been benchmarked.

Regression source is tests/test.c. Database used for this revision:
/media/iotteam/hd/lx/static-query-testdb-6.1-ops-identity
Run verify_object_candidates.py on the decoded evidence candidate CSV.
# Final ops query regression (2026-10-12)

Entry point: OpsConcurrentFreeUsePaths.ql. OpsValueSummaries.qll adds bounded
parameter-to-return summaries and nested private-getter wrapper summaries.
Each return summary pairs the actual argument with that same call's result,
rather than joining all calls to a shared wrapper. These summaries are used both
at dispatch sites and within callbacks. Existing field/private/container models
and concrete ops table bindings remain required.

The query includes a method paired with itself, as well as distinct methods.
Dispatch sites establish possible object association, not concurrent execution;
framework serialization and synchronization remain later review inputs. Sequential
test dispatch calls validate association only. No launch API is required.

Fixture: tests/ops_final_test.c (old cases preserved, new cases appended).
Database: /media/iotteam/hd/lx/static-query-testdb-6.1-ops-final.
Reproduce: bash ops/run_final_tests.sh from the server query pack.
The primary candidate query requires evidence; OpsUnresolvedObjects.ql is a
separate diagnostic query and must not be merged into primary candidates.

