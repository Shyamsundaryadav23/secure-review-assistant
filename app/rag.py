"""Retrieval over the CWE/OWASP knowledge base.
Uses sentence-transformers + FAISS if installed; otherwise a keyword-overlap fallback (always works)."""
import json
import logging
import os
import re

KB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cwe_kb.json")
logger = logging.getLogger(__name__)


def load_kb():
    with open(KB_PATH, encoding="utf-8") as f:
        return json.load(f)


def _text(k):
    return f'{k["title"]} {k["description"]} {k["insecure"]} {k["cwe"]}'


def _tok(s):
    return set(re.findall(r"[a-z0-9_]+", s.lower()))


class Retriever:
    def __init__(self, use_embeddings=True):
        self.kb = load_kb()
        self.mode = "keyword"
        if use_embeddings and os.environ.get("USE_EMBEDDINGS", "1") == "1":
            try:
                import faiss, numpy as np
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
                X = self.model.encode([_text(k) for k in self.kb], normalize_embeddings=True)
                self.index = faiss.IndexFlatIP(X.shape[1])
                self.index.add(np.array(X, dtype="float32"))
                self.np = np
                self.mode = "faiss"
            except Exception as exc:
                self.mode = "keyword"
                logger.warning(
                    "Embedding retrieval unavailable; using keyword retrieval: %s",
                    type(exc).__name__,
                )
        if self.mode == "keyword":
            self.toks = [_tok(_text(k)) for k in self.kb]

    def retrieve(self, query, k=3):
        if self.mode == "faiss":
            v = self.model.encode([query], normalize_embeddings=True)
            _, idx = self.index.search(self.np.array(v, dtype="float32"), k)
            return [self.kb[i] for i in idx[0] if i >= 0]
        q = _tok(query)
        scored = sorted(range(len(self.kb)), key=lambda i: -len(q & self.toks[i]) / (len(q) ** 0.5 + 1))
        return [self.kb[i] for i in scored[:k]]
