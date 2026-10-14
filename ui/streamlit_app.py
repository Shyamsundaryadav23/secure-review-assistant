import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.pipeline import MAX_CODE_CHARS, review

st.set_page_config(
    page_title="Secure Code Review",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    :root {
        --ink: #142b35;
        --muted: #617681;
        --line: #dce8e9;
        --teal: #087f78;
        --teal-dark: #075d5a;
        --mint: #e8f6f2;
        --surface: #ffffff;
        --canvas: #f4f8f7;
    }
    .stApp {
        background:
            radial-gradient(ellipse at 2% 0%, rgba(177, 225, 214, .28), transparent 34rem),
            var(--canvas);
        color: var(--ink);
        font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;
    }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stMainBlockContainer"] {
        max-width: 1180px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }
    h1, h2, h3, [data-testid="stMetricValue"] {
        font-family: 'Segoe UI', 'Helvetica Neue', sans-serif !important;
        color: var(--ink);
    }
    .hero {
        position: relative;
        overflow: hidden;
        padding: 2.1rem 2.25rem;
        margin: 0 0 1.5rem;
        border: 1px solid #cde3df;
        border-radius: 24px;
        background: linear-gradient(115deg, #e5f5f0 0%, #f6fbf9 58%, #e9f3f5 100%);
        box-shadow: 0 12px 34px rgba(27, 73, 75, .06);
    }
    .hero:after {
        content: ' ';
        position: absolute;
        width: 240px;
        height: 240px;
        right: 7%;
        top: -140px;
        border: 1px solid rgba(8, 127, 120, .14);
        border-radius: 50%;
        box-shadow: 0 0 0 30px rgba(8, 127, 120, .035), 0 0 0 60px rgba(8, 127, 120, .025);
        pointer-events: none;
    }
    .eyebrow {
        margin: 0 0 .55rem;
        color: var(--teal-dark);
        font-size: .73rem;
        font-weight: 700;
        letter-spacing: .12em;
        text-transform: uppercase;
    }
    .hero-title {
        position: relative;
        z-index: 1;
        margin: 0;
        color: var(--ink);
        font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;
        font-size: clamp(1.8rem, 4vw, 2.65rem);
        font-weight: 700;
        letter-spacing: -.045em;
        line-height: 1.08;
    }
    .hero-copy {
        position: relative;
        z-index: 1;
        max-width: 620px;
        margin: .8rem 0 0;
        color: #526c74;
        font-size: 1rem;
        line-height: 1.6;
    }
    .section-kicker {
        margin: 0 0 .35rem;
        color: var(--teal);
        font-size: .72rem;
        font-weight: 700;
        letter-spacing: .12em;
        text-transform: uppercase;
    }
    .helper-card {
        padding: 1.1rem 1.15rem;
        border: 1px solid var(--line);
        border-radius: 16px;
        background: rgba(255,255,255,.82);
    }
    .helper-title { margin: 0 0 .4rem; font-weight: 700; color: var(--ink); }
    .helper-copy { margin: 0; color: var(--muted); font-size: .9rem; line-height: 1.55; }
    .trust-note {
        padding: .85rem 1rem;
        border-left: 3px solid var(--teal);
        border-radius: 0 12px 12px 0;
        background: var(--mint);
        color: #315d5a;
        font-size: .86rem;
        line-height: 1.5;
    }
    .finding-heading {
        display: flex;
        align-items: center;
        gap: .65rem;
        flex-wrap: wrap;
    }
    .severity-pill {
        display: inline-flex;
        align-items: center;
        padding: .22rem .62rem;
        border-radius: 999px;
        font-size: .73rem;
        font-weight: 700;
        letter-spacing: .025em;
    }
    .severity-high { background: #fff0ec; color: #b43e2c; }
    .severity-medium { background: #fff6df; color: #8b6100; }
    .severity-low { background: #e8f5ee; color: #28714e; }
    .severity-info { background: #eaf1f5; color: #405d6d; }
    .small-muted { color: var(--muted); font-size: .84rem; }
    [data-testid="stMetric"] {
        padding: 1rem 1.05rem;
        border: 1px solid var(--line);
        border-radius: 16px;
        background: var(--surface);
        box-shadow: 0 4px 14px rgba(27, 73, 75, .035);
    }
    [data-testid="stMetricLabel"] { color: var(--muted); }
    [data-testid="stTextArea"] textarea {
        border-color: #cfdddf;
        border-radius: 14px;
        background: #fbfdfd;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: .88rem;
        line-height: 1.55;
    }
    [data-testid="stTextArea"] textarea:focus {
        border-color: var(--teal);
        box-shadow: 0 0 0 1px var(--teal);
    }
    [data-testid="stForm"] {
        padding: 1rem 1.1rem;
        border: 1px solid var(--line);
        border-radius: 18px;
        background: var(--surface);
        box-shadow: 0 6px 22px rgba(27, 73, 75, .04);
    }
    .stButton > button[kind="primary"], [data-testid="stFormSubmitButton"] button {
        min-height: 2.8rem;
        border: 0;
        border-radius: 11px;
        background: linear-gradient(100deg, #087f78, #096b70);
        color: white;
        font-weight: 700;
        box-shadow: 0 6px 14px rgba(8, 127, 120, .18);
    }
    .stButton > button[kind="primary"]:hover,
    [data-testid="stFormSubmitButton"] button:hover {
        border: 0;
        background: #075d5a;
        color: white;
    }
    [data-testid="stExpander"] {
        overflow: hidden;
        border: 1px solid var(--line);
        border-radius: 16px;
        background: white;
        box-shadow: 0 4px 14px rgba(27, 73, 75, .035);
    }
    [data-testid="stExpander"] summary { padding: .65rem .75rem; }
    div[data-testid="stCode"] {
        border: 1px solid #dce8e9;
        border-radius: 12px;
    }
    hr { border-color: var(--line); }
    @media (max-width: 700px) {
        [data-testid="stMainBlockContainer"] { padding: 1rem .8rem 3rem; }
        .hero { padding: 1.5rem 1.25rem; border-radius: 18px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

SAMPLE = '''import os, hashlib
API_KEY = "sk-live-12345678"

def get_user(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name='{name}'")

def ping(host):
    os.system("ping " + host)

h = hashlib.md5(b"x").hexdigest()
'''

st.markdown(
    """
    <div class="hero">
      <p class="eyebrow">Developer security · Python</p>
      <h1 class="hero-title">Review code with confidence.</h1>
      <p class="hero-copy">
        Catch common security risks, understand why they matter, and explore
        practical fixes—grounded in CWE and OWASP guidance.
      </p>
    </div>
    """,
    unsafe_allow_html=True,
)

input_col, guide_col = st.columns([1.8, 1], gap="large")
with input_col:
    st.markdown('<p class="section-kicker">01 · Your code</p>', unsafe_allow_html=True)
    st.markdown("### Start a review")
    st.caption("Paste a Python snippet or upload a `.py` file (up to 1 MB).")
    with st.form("review_form"):
        code_input = st.text_area(
            "Python source",
            SAMPLE,
            height=310,
            label_visibility="collapsed",
            placeholder="Paste Python code here…",
        )
        uploaded_file = st.file_uploader(
            "Choose a Python file",
            type=["py"],
            max_upload_size=1,
            help="Uploading a file replaces the pasted code for this review.",
        )
        submitted = st.form_submit_button("✦  Review my code", type="primary", use_container_width=True)

with guide_col:
    st.markdown('<p class="section-kicker">02 · How it works</p>', unsafe_allow_html=True)
    st.markdown("### A helpful first pass")
    st.markdown(
        """
        <div class="helper-card">
          <p class="helper-title">① Detect</p>
          <p class="helper-copy">Deterministic Python rules scan for common security patterns.</p>
        </div>
        <br>
        <div class="helper-card">
          <p class="helper-title">② Explain</p>
          <p class="helper-copy">CWE and OWASP references add context and practical remediation guidance.</p>
        </div>
        <br>
        <div class="helper-card">
          <p class="helper-title">③ Review</p>
          <p class="helper-copy">You decide what to accept. Suggested fixes are never applied automatically.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <div class="trust-note">
          <strong>Privacy first.</strong> Code stays local unless you explicitly
          choose to send it to Anthropic for explanations.
        </div>
        """,
        unsafe_allow_html=True,
    )
    allow_external_processing = st.checkbox(
        "Allow Anthropic explanations",
        value=False,
        help=(
            "When enabled, code is sent to Anthropic. Detected hard-coded credential "
            "lines are redacted first. Only share code you are authorized to send."
        ),
    )

if submitted:
    st.session_state.pop("review_result", None)
    try:
        if uploaded_file is not None:
            if uploaded_file.size > MAX_CODE_CHARS * 4:
                raise ValueError(f"Uploaded file exceeds the {MAX_CODE_CHARS:,}-character limit.")
            source = uploaded_file.read(MAX_CODE_CHARS * 4 + 1).decode("utf-8")
        else:
            source = code_input
        if len(source) > MAX_CODE_CHARS:
            raise ValueError(f"Code must be no longer than {MAX_CODE_CHARS:,} characters.")

        api_url = os.environ.get("REVIEW_API_URL")
        if api_url:
            request = Request(
                api_url.rstrip("/") + "/review",
                data=json.dumps(
                    {
                        "code": source,
                        "allow_external_processing": allow_external_processing,
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=180) as response:
                result = json.loads(response.read().decode("utf-8"))
        else:
            result = review(source, allow_external_processing=allow_external_processing)
        st.session_state["review_result"] = result
        st.session_state["review_id"] = st.session_state.get("review_id", 0) + 1
        st.session_state["review_decisions"] = {}
    except UnicodeDecodeError:
        st.error("This file is not valid UTF-8 text. Try saving it as UTF-8 and upload again.")
    except ValueError as exc:
        st.error(str(exc))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        st.error(f"Review service returned HTTP {exc.code}: {detail}")
    except URLError as exc:
        st.error(f"Could not connect to the review service: {exc.reason}")

result = st.session_state.get("review_result")
if result is not None:
    st.divider()
    st.markdown('<p class="section-kicker">03 · Review results</p>', unsafe_allow_html=True)
    st.markdown("### Your security snapshot")

    if result["syntax_error"]:
        error = result["syntax_error"]
        st.error(f"Python syntax error on line {error['line']}: {error['msg']}")
        st.info("Correct the syntax error, then run the review again.")
    else:
        findings = result["findings"]
        high_count = sum(finding["severity"].lower() == "high" for finding in findings)
        medium_count = sum(finding["severity"].lower() == "medium" for finding in findings)
        low_count = sum(finding["severity"].lower() == "low" for finding in findings)
        metric_cols = st.columns(4)
        metric_cols[0].metric("Findings", len(findings))
        metric_cols[1].metric("High", high_count)
        metric_cols[2].metric("Medium", medium_count)
        metric_cols[3].metric("Scan time", f"{result['latency_ms']} ms")
        st.caption(
            f"Knowledge retrieval: {result['retrieval_mode']} · "
            "This automated review is advisory, not a guarantee of security."
        )

        if not findings:
            st.success("No issues matched the current rules.")
            st.info(result["note"])
        else:
            decisions = st.session_state.setdefault("review_decisions", {})
            review_id = st.session_state["review_id"]
            for index, finding in enumerate(findings):
                key = f"{review_id}:{index}"
                severity = finding["severity"].lower()
                badge_class = f"severity-{severity}" if severity in {"high", "medium", "low"} else "severity-info"
                heading = (
                    f'<span class="finding-heading">'
                    f'<span class="severity-pill {badge_class}">{finding["severity"]} priority</span>'
                    f'<strong>{finding["rule"]}</strong>'
                    f'<span class="small-muted">Line {finding["line"]} · {finding["cwe"]}</span>'
                    f'</span>'
                )
                with st.expander(
                    f"{finding['severity']} · {finding['rule']} · Line {finding['line']}",
                    expanded=index == 0,
                ):
                    st.markdown(heading, unsafe_allow_html=True)
                    st.markdown("")
                    st.markdown(f"**What was detected**  \n{finding['why']}")
                    st.markdown(
                        f"**Why it matters**  \n{finding['explanation']}"
                    )
                    st.markdown("**Suggested remediation**")
                    st.code(finding["fix"], language="python")
                    with st.expander("View CWE / OWASP evidence"):
                        st.markdown(f"**OWASP category:** {finding['owasp']}")
                        for evidence in finding["evidence"]:
                            st.markdown(
                                f"- [{evidence['cwe']} — {evidence['title']}]({evidence['source']})"
                            )
                        st.caption(
                            f"Retrieval matched this rule: "
                            f"{'Yes' if finding['retrieval_hit'] else 'No — canonical rule reference shown'} · "
                            f"Explanation source: {finding['explanation_source']}"
                        )
                    decision = decisions.get(key)
                    if decision:
                        if decision == "Accepted":
                            st.success("Marked accepted for human review. No source code was changed.")
                        else:
                            st.info("Marked rejected for human review. No source code was changed.")
                    else:
                        accept_col, reject_col, _ = st.columns([1, 1, 3])
                        if accept_col.button("✓  Accept", key=f"accept-{key}"):
                            decisions[key] = "Accepted"
                            st.rerun()
                        if reject_col.button("✕  Reject", key=f"reject-{key}"):
                            decisions[key] = "Rejected"
                            st.rerun()

st.markdown("---")
st.caption(
    "Secure Code Review Assistant · Python static checks with CWE/OWASP context · "
    "Always combine automated checks with human review."
)
