"""Grounded explanation layer; external processing requires an explicit request opt-in."""
import logging
import os
import re

logger = logging.getLogger(__name__)

SECRET_LINE = re.compile(r"""(['"])[^'"\n]{4,}\1""")


def redact(code, findings):
    """Remove string literals on lines flagged as secrets before sending code to an external API."""
    lines = code.splitlines()
    for f in findings:
        if f["rule"] == "SECRET" and 0 < f["line"] <= len(lines):
            lines[f["line"] - 1] = SECRET_LINE.sub('"<REDACTED>"', lines[f["line"] - 1])
    return "\n".join(lines)


def offline_explain(finding, evidence):
    e = evidence[0]
    return (
        f"{e['title']} ({e['cwe']}, {e['owasp']}). {e['description']} "
        f"Suggested fix: {e['fix']}"
    )


def llm_explain(snippet, finding, evidence):
    import anthropic
    ev = "\n".join(
        f"- {e['cwe']} {e['title']}: {e['description']} Fix: {e['fix']}"
        for e in evidence
    )
    prompt = (
        "You are a secure code reviewer. Use ONLY the evidence below. Explain the issue in 2-3 sentences, "
        f"give a minimal patched code line, and cite exactly {finding['cwe']}. "
        "If the evidence does not support the finding, reply exactly: ABSTAIN.\n\n"
        f"Code:\n{snippet}\n\n"
        f"Finding: line {finding['line']} - {finding['why']} ({finding['cwe']})\n\n"
        f"Evidence:\n{ev}"
    )
    client = anthropic.Anthropic()
    r = client.messages.create(
        model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5"),
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return r.content[0].text.strip()


def guarded_explain(snippet, finding, evidence, allow_external_processing=False):
    """Cite-or-abstain guard. Returns (text, source) where source in {llm, offline, offline-fallback}."""
    if not evidence:
        return "No matching CWE/OWASP evidence was retrieved; explanation abstained.", "offline-fallback"
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return offline_explain(finding, evidence), "offline"
    if not allow_external_processing:
        return offline_explain(finding, evidence), "offline"
    try:
        text = llm_explain(redact(snippet, [finding]), finding, evidence)
    except Exception as ex:
        logger.warning(
            "Anthropic explanation failed; using grounded offline explanation: %s",
            type(ex).__name__,
        )
        return (
            offline_explain(finding, evidence) + f" (LLM unavailable: {type(ex).__name__})",
            "offline-fallback",
        )
    cited = {e["cwe"] for e in evidence}
    response_citations = set(re.findall(r"\bCWE-\d+\b", text))
    expected_cwe = finding["cwe"]
    if text.strip() == "ABSTAIN" or expected_cwe not in cited or expected_cwe not in response_citations:
        return offline_explain(finding, evidence), "offline-fallback"  # guardrail: no valid citation
    return text, "llm"
