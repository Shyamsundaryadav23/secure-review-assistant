"""scan -> retrieve -> explain (guarded) -> report."""
import time
from threading import Lock

from .scanner import scan
from .rag import Retriever
from .llm import guarded_explain, redact

_R = None
_R_LOCK = Lock()
MAX_CODE_CHARS = 100_000


def retriever():
    global _R
    if _R is None:
        with _R_LOCK:
            if _R is None:
                _R = Retriever()
    return _R


def review(code, allow_external_processing=False):
    if not isinstance(code, str) or not code.strip():
        raise ValueError("Code must contain at least one non-whitespace character.")
    if len(code) > MAX_CODE_CHARS:
        raise ValueError(f"Code must be no longer than {MAX_CODE_CHARS:,} characters.")

    t0 = time.perf_counter()
    findings, syntax_error = scan(code)
    if syntax_error:
        return {
            "syntax_error": syntax_error,
            "findings": [],
            "retrieval_mode": retriever().mode,
            "note": "Code could not be parsed. Fix the syntax error first.",
            "latency_ms": 0,
        }
    r = retriever()
    sanitized_code = redact(code, findings)
    for f in findings:
        retrieved = r.retrieve(f"{f['why']} {f['rule']}", k=3)
        f["retrieval_hit"] = any(e["rule"] == f["rule"] for e in retrieved)
        canonical = next((entry for entry in r.kb if entry["rule"] == f["rule"]), None)
        if canonical is None:
            raise RuntimeError(f"No CWE/OWASP knowledge-base entry for scanner rule {f['rule']}.")
        evidence = [canonical] + [entry for entry in retrieved if entry["rule"] != f["rule"]][:2]
        f["evidence"] = [{"cwe": e["cwe"], "title": e["title"], "source": e["source"]} for e in evidence]
        f["cwe"], f["owasp"], f["fix"] = canonical["cwe"], canonical["owasp"], canonical["fix"]
        f["explanation"], f["explanation_source"] = guarded_explain(
            sanitized_code, f, evidence, allow_external_processing=allow_external_processing
        )
    return {
        "syntax_error": None,
        "findings": findings,
        "retrieval_mode": r.mode,
        "note": (
            ""
            if findings
            else "No rule-based issue found. This does not prove the code is secure; get a human review."
        ),
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
