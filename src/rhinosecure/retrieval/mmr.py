"""Maximal Marginal Relevance reranking (Carbonell & Goldstein, 1998) --
CLAUDE.md Section 4's "retrieve a wider candidate set, then rerank down to
roughly 5-8 items" step. Generic over whatever a retrieval backend (today,
retrieval.vector.VectorIndex; the interface doesn't care) supplies a
relevance and similarity function for. Nothing here is ATT&CK-specific.

Balances relevance (how well a candidate matches the query) against
redundancy (how similar it is to items already picked), so the returned set
covers different facets of the evidence instead of restating the same one
several times -- CLAUDE.md's own example: "description, exploitation status,
technique mapping, mitigation" rather than eight restatements of the same
CVSS score.
"""

from __future__ import annotations

from typing import Callable, Hashable, Sequence, TypeVar

T = TypeVar("T", bound=Hashable)

# Equal weight to relevance and diversity -- CLAUDE.md does not prescribe a
# value, and this is the conventional default in the MMR literature.
DEFAULT_LAMBDA = 0.5


def rerank(
    candidates: Sequence[T],
    *,
    relevance: dict[T, float] | Callable[[T], float],
    similarity: Callable[[T, T], float],
    k: int,
    lambda_param: float = DEFAULT_LAMBDA,
) -> list[T]:
    """Greedily selects up to `k` items from `candidates`, balancing
    relevance to the query against similarity to items already selected.

    `relevance` gives each candidate's similarity to the query (Sim1 in the
    original MMR paper); `similarity` gives pairwise similarity between two
    candidates (Sim2). `lambda_param` in [0, 1]: 1.0 is pure relevance
    ranking (equivalent to just taking the top `k` of `candidates` as
    ordered, without diversity), 0.0 is pure diversity (ignores relevance
    past the first pick).

    `candidates` should already be the *wide* pool from a first-pass
    retrieval (see VectorIndex.search) -- MMR reranks a pool wider than `k`,
    it does not do first-pass retrieval itself.
    """
    if not 0.0 <= lambda_param <= 1.0:
        raise ValueError(f"lambda_param must be in [0, 1], got {lambda_param}")

    relevance_of = relevance.__getitem__ if isinstance(relevance, dict) else relevance

    remaining = list(candidates)
    selected: list[T] = []

    while remaining and len(selected) < k:

        def mmr_score(candidate: T) -> float:
            redundancy = max((similarity(candidate, s) for s in selected), default=0.0)
            return lambda_param * relevance_of(candidate) - (1 - lambda_param) * redundancy

        best = max(remaining, key=mmr_score)
        selected.append(best)
        remaining.remove(best)

    return selected
