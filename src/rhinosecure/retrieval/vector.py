"""TF-IDF vector space + cosine similarity: the "vector retrieval" half of
CLAUDE.md Section 4's structured-lookup-vs-vector-retrieval split, for prose
where the query genuinely is not an exact key. General-purpose over any
corpus of (doc_id, text) pairs -- ATT&CK technique descriptions today,
vendor remediation guidance or mitigation writeups later, per Section 4's
own examples. Nothing here is ATT&CK-specific.

CLAUDE.md Section 11 names chromadb or faiss-cpu for this. Neither fits as
shipped in this environment (Python 3.14): chromadb 1.1.1's Settings class
subclasses pydantic.v1.BaseSettings, and pydantic's v1-compat shim does not
support Python 3.14 -- confirmed by actually running it, which raised
`ConfigError: unable to infer type for attribute "chroma_server_nofile"`
before a single document was ever embedded, not a hypothetical concern.
faiss-cpu installs cleanly, but it is a nearest-neighbor *search* index, not
an embedding generator -- it still needs vectors from somewhere, and over
~500 short documents brute-force cosine similarity is already fast enough
that an ANN index buys nothing. A real embedding model
(sentence-transformers) would pull in torch for a corpus this small.

TF-IDF needs none of that: no new dependency, fully local and deterministic
(the same offline/reproducibility bar as the rest of Slice 2), and -- not
incidentally -- the exact substrate Carbonell & Goldstein's original MMR
paper (CLAUDE.md Section 4, CP3) was built and evaluated on, predating
neural embeddings by over a decade. Swappable later behind this module's
interface (`VectorIndex`) if a working embedding backend becomes available;
nothing outside this module needs to know which one is in use.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")

# Function words carry no content signal regardless of domain -- standard IR
# practice, not something tuned to any one corpus. Domain-specific "noise"
# words (generic to a genre of writing, like CVE-advisory boilerplate) are
# deliberately NOT hand-listed here the way enrich/attack.py's old
# keyword-overlap tier had to: a term absent from the corpus's own
# vocabulary already contributes zero weight (see VectorIndex.embed_query),
# and a term present but common within the corpus is already down-weighted
# by IDF in proportion to how common it actually is there -- no manual list
# to maintain or accidentally tune to one fixture.
_STOPWORDS = frozenset(
    """
    a an the of to in on for and or is are this that these those be been being
    may can will allow allows allowed allowing using used use via with without
    by as at from into when which who whom its their they them not no nor if
    then than but also over under out up down
    """.split()
)


def tokenize(text: str) -> list[str]:
    return [tok for tok in _TOKEN_PATTERN.findall(text.lower()) if tok not in _STOPWORDS]


@dataclass(frozen=True)
class Vector:
    """A sparse TF-IDF vector: term -> weight, plus its precomputed L2 norm."""

    weights: dict[str, float]
    norm: float


def cosine_similarity(a: Vector, b: Vector) -> float:
    if a.norm == 0.0 or b.norm == 0.0:
        return 0.0
    smaller, larger = (a, b) if len(a.weights) <= len(b.weights) else (b, a)
    dot = sum(weight * larger.weights.get(term, 0.0) for term, weight in smaller.weights.items())
    return dot / (a.norm * b.norm)


class VectorIndex:
    """A TF-IDF vector space fit to a fixed corpus, ready for similarity
    search and pairwise similarity (the two primitives retrieval.mmr needs)."""

    def __init__(self, documents: dict[str, str]):
        self._doc_ids = list(documents.keys())
        term_freqs_by_doc = {doc_id: Counter(tokenize(text)) for doc_id, text in documents.items()}

        doc_freq: Counter[str] = Counter()
        for freqs in term_freqs_by_doc.values():
            doc_freq.update(freqs.keys())

        n = len(documents)
        # Standard smoothed IDF: log(N/df) alone hits exactly 0 for a term
        # in every document (plausible here -- a Windows-filtered corpus may
        # well have "windows" in all of them), which would drop that term's
        # dimension entirely rather than just down-weighting it.
        self._idf = {term: math.log(n / df) + 1.0 for term, df in doc_freq.items()}
        self._vectors: dict[str, Vector] = {
            doc_id: self._make_vector(term_freqs_by_doc[doc_id]) for doc_id in self._doc_ids
        }

    def _make_vector(self, term_freqs: Counter[str]) -> Vector:
        weights = {
            term: freq * self._idf[term] for term, freq in term_freqs.items() if term in self._idf
        }
        norm = math.sqrt(sum(w * w for w in weights.values()))
        return Vector(weights=weights, norm=norm)

    def embed_query(self, text: str) -> Vector:
        """Embeds free text (e.g. a finding's product/evidence) in the
        corpus's own vector space. A term the corpus never saw contributes
        nothing -- same as any vector space model, and why no separate
        boilerplate-stripping step is needed on the query side either."""
        return self._make_vector(Counter(tokenize(text)))

    def similarity(self, doc_id_a: str, doc_id_b: str) -> float:
        return cosine_similarity(self._vectors[doc_id_a], self._vectors[doc_id_b])

    def search(self, query: str, top_k: int) -> list[tuple[str, float]]:
        """The top_k documents closest to `query` by cosine similarity,
        most similar first -- deliberately the *wide* candidate set CLAUDE.md
        Section 4 asks for. Callers rerank it down with retrieval.mmr before
        presenting results; this method does first-pass retrieval only."""
        query_vector = self.embed_query(query)
        scored = [
            (doc_id, cosine_similarity(query_vector, vector))
            for doc_id, vector in self._vectors.items()
        ]
        scored = [(doc_id, score) for doc_id, score in scored if score > 0.0]
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored[:top_k]
