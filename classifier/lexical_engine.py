"""
Lexical Signal Engine — BM25 & Subword Character N-Gram Matching.

Ingests declarative lexicons from SecurityKnowledgeBundle:
1. BM25 Lexical Term Frequency scoring
2. Subword Character N-Grams (3-5 chars) for morphological distortion resilience
3. Sensitive keyword dictionary scanning across languages
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Any

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class BM25Ranker:
    """High-performance inverted-index BM25 term weighting ranker."""

    def __init__(self, corpus: list[str], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.corpus = corpus
        self.doc_len = [len(self._tokenize(doc)) for doc in corpus]
        self.avg_doc_len = sum(self.doc_len) / max(1, len(corpus))
        self.inverted_index: dict[str, list[tuple[int, int]]] = {}
        doc_freqs: dict[str, int] = Counter()

        for doc_idx, doc in enumerate(corpus):
            tokens = self._tokenize(doc)
            counts = Counter(tokens)
            for token, count in counts.items():
                self.inverted_index.setdefault(token, []).append((doc_idx, count))
                doc_freqs[token] += 1

        self.idf: dict[str, float] = {}
        n_docs = len(corpus)
        for term, df in doc_freqs.items():
            self.idf[term] = math.log(1 + (n_docs - df + 0.5) / (df + 0.5))

    def _tokenize(self, text: str) -> list[str]:
        return re.findall(r'\b\w+\b', text.lower())

    def get_score(self, query_tokens: list[str]) -> float:
        """Returns max BM25 score against corpus using inverted index."""
        if not query_tokens or not self.corpus:
            return 0.0

        scores: dict[int, float] = {}
        unique_q = set(query_tokens)
        for q in unique_q:
            if q not in self.inverted_index:
                continue
            idf = self.idf.get(q, 0.1)
            for doc_idx, tf in self.inverted_index[q]:
                doc_len = self.doc_len[doc_idx]
                num = tf * (self.k1 + 1)
                denom = tf + self.k1 * (1 - self.b + self.b * (doc_len / max(1, self.avg_doc_len)))
                scores[doc_idx] = scores.get(doc_idx, 0.0) + idf * (num / denom)

        return max(scores.values(), default=0.0)


class LexicalSignalEngine:
    """4-Tier Lexical Engine (Exact, Regex, BM25, Character N-Grams) using declarative security knowledge."""

    def __init__(self, adv_lexicon: list[str] | None = None, benign_lexicon: list[str] | None = None) -> None:
        bundle = KnowledgeLoader.get_bundle()
        adv_lexicon = adv_lexicon or bundle.adversarial_lexicon
        benign_lexicon = benign_lexicon or bundle.benign_lexicon

        self.inquiry_prefixes = bundle.inquiry_prefixes
        self.quoted_inquiry_markers = bundle.quoted_inquiry_markers
        self.morphological_roots = bundle.morphological_roots

        self.adv_bm25 = BM25Ranker(adv_lexicon)
        self.benign_bm25 = BM25Ranker(benign_lexicon)

    def _get_char_ngrams(self, text: str, n_range: tuple[int, int] = (3, 5)) -> set[str]:
        """Extract character n-grams from text."""
        cleaned = re.sub(r'\s+', '', text.lower())
        ngrams = set()
        for n in range(n_range[0], min(n_range[1] + 1, len(cleaned) + 1)):
            for i in range(len(cleaned) - n + 1):
                ngrams.add(cleaned[i:i + n])
        return ngrams

    def _is_inquiry_or_educational(self, text: str) -> bool:
        t = text.strip().lower()
        if self.inquiry_prefixes and t.startswith(self.inquiry_prefixes):
            return True
        if '"' in t or "'" in t or '«' in t or '“' in t or '”' in t:
            if any(p in t for p in self.quoted_inquiry_markers):
                return True
        return False

    def evaluate_lexical(self, text: str) -> dict[str, float]:
        """
        Evaluate lexical threat score using contrastive BM25 and n-gram overlap.
        """
        if self._is_inquiry_or_educational(text):
            return {}

        scores: dict[str, float] = {}
        tokens = re.findall(r'\b\w+\b', text.lower())

        adv_bm25_score = self.adv_bm25.get_score(tokens)
        benign_bm25_score = self.benign_bm25.get_score(tokens)

        # Contrastive BM25 check
        if adv_bm25_score > 3.5 and adv_bm25_score > benign_bm25_score * 1.5:
            normalized_bm25 = min(1.0, 0.60 + (adv_bm25_score / 15.0))
            scores["lexical_bm25_threat"] = normalized_bm25

        # Subword morphological check (resilience to character repetition like هكّرررر or قرصنةةة)
        query_ngrams = self._get_char_ngrams(text)
        if query_ngrams and self.morphological_roots:
            matched_roots = [r for r in self.morphological_roots if any(r in ng for ng in query_ngrams)]
            if matched_roots:
                scores["lexical_subword_threat"] = 0.85

        return scores
