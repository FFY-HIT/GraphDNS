# VeriDNS Paper-to-Code Mapping

This document records exactly which statements in the VeriDNS paper are
implemented and which details are unavailable. It is part of the experiment's
validity boundary.

## Implemented statements

| Paper description | Reproduction |
| --- | --- |
| RSG is a labelled directed multigraph | `exp3.veridns.PaperRSG` |
| Every RR becomes `(owner, type, rdata)` | `PaperRSG.from_case()` |
| Undefined targets are retained as graph stubs | every rdata endpoint is retained even without outgoing edges |
| Insert/delete/update becomes a graph delta | `record_deltas()` |
| Impact analysis starts from delta nodes | `_record_nodes()` seeds `paper_affected_nodes()` |
| Backward traversal finds predecessor paths | reverse adjacency in `paper_affected_nodes()` |
| Forward traversal finds successor paths | forward adjacency in `paper_affected_nodes()` |
| Their union is the affected subgraph | one bidirectional closure is returned |
| Only connected prior results are revalidated | `veridns_incremental_paths()` |

For static path comparison, the finite concrete resolver first materializes
every RR transition needed by the declared bounded query set. States
representing the same RSG entity are then merged, and paths are traversed
without a persistent alpha/beta assignment. This gives the RSG reproduction
all oracle transitions and isolates the effect of composing transitions from
incompatible query bindings. It is therefore more conservative than simply
stopping at unresolved DNAME or wildcard stubs.

## Conservative choices in favor of VeriDNS

1. Incremental impact traversal uses the union of pre-update and post-update
   RSG edges. Deleted predecessor edges therefore remain available to impact
   analysis.
2. Once a query is marked affected, it is recomputed over the complete
   post-update RSG rather than only the affected subgraph.
3. The static comparison gives the reproduced RSG every transition observed
   in the bounded concrete oracle, so missing transition-expansion details do
   not reduce its Recall.

Consequently, update mismatches reported by the experiment arise because an
old query path is not connected to the changed explicit RSG endpoints, not
because the reproduction artificially restricts revalidation.

## Details not specified by the paper

The paper does not provide executable pseudocode for:

- DNAME prefix binding across multiple transitions;
- exact-owner versus wildcard priority;
- delegation/DNAME shadowing dependencies that are not explicit RR edges;
- cache invalidation keys for a newly added owner;
- report-set reconciliation after local checking.

GraphDNS represents these relations through alpha/beta bindings, reachability
labels, semantic edge origins, and coverage indexes. The default update
workload targets these dependency differences using controlled single-record
changes superimposed on complete `bme.hu` and `cmu.edu` configurations selected
from Census. The background records are real; the changes are controlled
interventions rather than observed historical updates.

## Artifact status

The paper points to:

```text
https://github.com/KaiQiangHu996/VeriDNS
```

The repository returned HTTP 404 when this reproduction was prepared.
Accordingly, every output uses the label `VeriDNS-RSG reproduction`; it must
not be relabelled as a measurement of the unavailable official code.
