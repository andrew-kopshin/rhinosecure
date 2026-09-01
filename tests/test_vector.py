import pytest

from rhinosecure.retrieval.vector import VectorIndex, tokenize


def test_tokenize_lowercases_and_strips_stopwords():
    tokens = tokenize("The Quick Fox and the Lazy Dog")
    assert tokens == ["quick", "fox", "lazy", "dog"]


def test_identical_documents_are_maximally_similar():
    index = VectorIndex(
        {
            "a": "malformed DHCP request triggers memory disclosure",
            "b": "malformed DHCP request triggers memory disclosure",
            "c": "completely unrelated text about printers and spoolers",
        }
    )
    assert index.similarity("a", "b") == pytest.approx(1.0)
    assert index.similarity("a", "c") < index.similarity("a", "b")


def test_disjoint_documents_have_zero_similarity():
    index = VectorIndex({"a": "dhcp server request", "b": "print spooler job"})
    assert index.similarity("a", "b") == pytest.approx(0.0)


def test_search_ranks_the_more_similar_document_first():
    index = VectorIndex(
        {
            "dhcp_spoofing": "Adversaries may spoof DHCP responses to redirect victim network traffic.",
            "print_processors": "Adversaries may abuse print processors to run malicious code as SYSTEM.",
            "unrelated": "Adversaries may collect data from cloud storage objects.",
        }
    )
    results = index.search("Malformed DHCP request triggers disclosure of server memory", top_k=3)
    assert results[0][0] == "dhcp_spoofing"
    assert results[0][1] > 0.0


def test_search_respects_top_k_and_excludes_zero_similarity():
    index = VectorIndex(
        {
            "match": "dhcp server request memory",
            "no_overlap": "print spooler job persistence",
        }
    )
    results = index.search("dhcp memory", top_k=5)
    assert [doc_id for doc_id, _score in results] == ["match"]


def test_query_term_absent_from_corpus_contributes_nothing():
    index = VectorIndex({"a": "dhcp server request"})
    # "zzzznotarealword" never appears anywhere in the corpus -- must not
    # raise, and must not be treated as if it matched something.
    vector = index.embed_query("dhcp zzzznotarealword")
    assert "zzzznotarealword" not in vector.weights


def test_common_term_is_downweighted_relative_to_rare_term():
    """The core IDF claim: a term nearly every document shares should count
    for less than a term only one document has, so a query matching on the
    rare term ranks that document above one that only shares the common
    term. This is what lets enrich/attack.py drop its old hand-curated
    boilerplate stopword list -- IDF does that job from the corpus itself."""
    index = VectorIndex(
        {
            "shares_common_only": "windows adversaries may access windows system windows resources",
            "shares_rare_term": "windows dhcpspecificmarker",
            "filler_1": "windows generic technique description text",
            "filler_2": "windows generic technique description text",
            "filler_3": "windows generic technique description text",
        }
    )
    results = index.search("windows dhcpspecificmarker", top_k=5)
    ranked_ids = [doc_id for doc_id, _score in results]
    assert ranked_ids[0] == "shares_rare_term"
