# Ops evidence levels

Use `OpsLifetimeCandidates.ql` as the recall view alongside the existing
`OpsConcurrentFreeUsePaths.ql` strict view. A candidate is not a confirmed UAF
or concurrency defect. Framework serialization, callback ordering, lifetime
ownership and reachability still require review.

`OpsCandidateLevels.ql` reports the strongest available evidence per access:

1. One concrete initialized table and compatible concrete struct pointer
   parameter types. Discovery only; no object identity claim.
2. The released parameter-relative object path covers the accessed member path.
   This is a lifetime-compatible candidate, not proof of the same runtime instance.
3. Actual dispatch sites have a common modeled argument origin. Table binding
   to the receiver may still be unresolved.
4. The dispatch receivers additionally have a common origin bound to the table.
   Concurrency and execution order remain unverified.

The default recall view requires level 2 or higher and distinct callback
implementations. Same-callback accesses remain available in the diagnostic view
and original strict query. The original strict query is unchanged: it supports
additional pointer types and does not require the recall view's path coverage.
The two views therefore are complementary, not an identical nested result set.

`OpsCandidateStages.ql` counts source tuples at each stage. Counts can exceed
CSV rows because projection collapses internal alternatives.
`OpsCandidateDispatchWitnesses.ql` exposes common runtime argument witnesses
for distinct callback implementations.

Real driver evaluation (seven existing single-file databases, 2026-10-13):

| Driver | Discovery rows | Default recall rows | Release-site/use-callback groups | Level 3/4 stage tuples |
| --- | ---: | ---: | ---: | ---: |
| rtsx | 201 | 33 | 2 | 0 |
| e1000 | 477 | 122 | 1 | 0 |
| usbatm | 117 | 0 | 0 | 0 |
| xhci-dbgtty | 0 | 0 | 0 | 0 |
| video-i2c | 0 | 0 | 0 | 0 |
| tun | 0 | 0 | 0 | 0 |
| sched-fence | 0 | 0 | 0 | 0 |

Rtsx candidates relate remove's releases of pcr/handle to shutdown's uses.
E1000 candidates relate remove's free_netdev to shutdown's netdev uses.
PCI lifecycle serialization must be reviewed before claiming a race. Usbatm's
covered paths only produced same-callback pairs, which the recall view excludes.
The other four databases did not yield modeled bound free callbacks: relaxing
dispatch requirements does not address their missing release evidence.

Keep level 2 as a provisional recall threshold on this sample. Do not lower it
to type-only matching to inflate counts. Larger driver/framework databases and
release summaries are the next step for improving level 3/4 coverage.

Limitations: only concrete struct pointer parameters are admitted by the recall
view; void pointers, sibling object relations, array-only dereferences and
framework ownership relations need additional precise models. Four existing
single-file databases (including tun) have known extractor errors; counts are
coverage observations, not complete negative findings. Textual member paths
are contextual evidence and can be ambiguous for unmodeled conversions.
