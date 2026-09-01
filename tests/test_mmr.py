import pytest

from rhinosecure.retrieval import mmr

# A redundant cluster (a, b, c mutually near-identical, all fairly relevant)
# plus one dissimilar-but-still-relevant item (d). Plain top-k-by-relevance
# would return the whole cluster; MMR should break it up.
_RELEVANCE = {"a": 0.9, "b": 0.85, "c": 0.8, "d": 0.3}
_SIMILARITY = {
    frozenset({"a", "b"}): 0.95,
    frozenset({"a", "c"}): 0.95,
    frozenset({"b", "c"}): 0.95,
    frozenset({"a", "d"}): 0.0,
    frozenset({"b", "d"}): 0.0,
    frozenset({"c", "d"}): 0.0,
}


def _similarity(x: str, y: str) -> float:
    if x == y:
        return 1.0
    return _SIMILARITY[frozenset({x, y})]


def test_diversifies_away_from_a_redundant_cluster():
    plain_top_2 = sorted(_RELEVANCE, key=lambda item: -_RELEVANCE[item])[:2]
    assert plain_top_2 == ["a", "b"]  # what you'd get without MMR

    result = mmr.rerank(
        list(_RELEVANCE), relevance=_RELEVANCE, similarity=_similarity, k=2, lambda_param=0.5
    )

    assert result[0] == "a"  # most relevant item still wins the first slot
    assert result[1] == "d"  # second slot goes to the diverse item, not the redundant "b"


def test_lambda_one_is_equivalent_to_plain_relevance_ranking():
    result = mmr.rerank(
        list(_RELEVANCE), relevance=_RELEVANCE, similarity=_similarity, k=3, lambda_param=1.0
    )
    assert result == ["a", "b", "c"]


def test_lambda_zero_ignores_relevance_after_the_first_pick():
    # With redundancy the only factor once selected is nonempty, the lowest-
    # relevance-but-most-different item should still win over more items
    # from the already-picked cluster.
    result = mmr.rerank(
        list(_RELEVANCE), relevance=_RELEVANCE, similarity=_similarity, k=2, lambda_param=0.0
    )
    assert result[1] == "d"


def test_k_larger_than_candidates_returns_all_of_them():
    result = mmr.rerank(["a", "b"], relevance=_RELEVANCE, similarity=_similarity, k=10)
    assert set(result) == {"a", "b"}


def test_empty_candidates_returns_empty():
    assert mmr.rerank([], relevance={}, similarity=_similarity, k=5) == []


def test_k_zero_returns_empty():
    result = mmr.rerank(list(_RELEVANCE), relevance=_RELEVANCE, similarity=_similarity, k=0)
    assert result == []


def test_relevance_accepts_a_callable_not_just_a_dict():
    result = mmr.rerank(
        list(_RELEVANCE), relevance=_RELEVANCE.__getitem__, similarity=_similarity, k=2
    )
    assert result[0] == "a"


@pytest.mark.parametrize("bad_lambda", [-0.1, 1.1])
def test_rejects_lambda_outside_zero_one(bad_lambda):
    with pytest.raises(ValueError):
        mmr.rerank(list(_RELEVANCE), relevance=_RELEVANCE, similarity=_similarity, k=2, lambda_param=bad_lambda)
