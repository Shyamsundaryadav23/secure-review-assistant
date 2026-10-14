"""Run:  python evaluate.py   -> precision/recall, retrieval hit rate, latency (copy numbers into report Section 5)."""
import time, statistics
from app.scanner import scan
from app.pipeline import retriever
from tests.cases import CASES

tp = fp = fn = hits = total = 0
lat = []
r = retriever()
for name, code, exp in CASES:
    t = time.perf_counter()
    findings, _ = scan(code)
    lat.append((time.perf_counter() - t) * 1000)
    got = {f["rule"] for f in findings}
    tp += len(got & exp); fp += len(got - exp); fn += len(exp - got)
    for f in findings:
        total += 1
        hits += any(e["rule"] == f["rule"] for e in r.retrieve(f"{f['why']} {f['rule']}", 3))
    print(("PASS " if got == exp else "FAIL "), name, sorted(exp), sorted(got))
print(f"\nCases={len(CASES)} TP={tp} FP={fp} FN={fn}")
print(f"Precision={tp/(tp+fp):.2f} Recall={tp/(tp+fn):.2f}")
print(f"Retrieval hit@3={hits}/{total} ({hits/total:.2f}) mode={r.mode}")
print(f"Scanner latency ms mean={statistics.mean(lat):.3f} max={max(lat):.3f}")
