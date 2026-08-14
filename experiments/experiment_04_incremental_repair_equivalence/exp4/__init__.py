"""Experiment 04: repair quality and incremental/full equivalence."""

SUPPORTED_REPAIR_KINDS = frozenset(
    {"LD", "DI", "MG", "CZD", "RL", "RB", "ML", "STALE"}
)
SEVERE_KINDS = frozenset({"LD", "MG", "CZD", "RL", "RB", "ML"})
