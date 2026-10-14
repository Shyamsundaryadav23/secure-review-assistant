import pytest
from fastapi.testclient import TestClient

from app import llm, pipeline
from app.api import app
from app.rag import Retriever

client = TestClient(app)


@pytest.fixture(autouse=True)
def use_keyword_retrieval(monkeypatch):
    monkeypatch.setattr(pipeline, "_R", Retriever(use_embeddings=False))


def test_review_returns_grounded_finding():
    response = client.post(
        "/review",
        json={"code": 'def get(cur, name):\n    cur.execute(f"SELECT * FROM users WHERE name=\'{name}\'")'},
    )

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["rule"] == "SQLI"
    assert finding["cwe"] == "CWE-89"
    assert finding["retrieval_hit"] is True
    assert finding["explanation_source"] == "offline"


def test_anthropic_requires_per_request_opt_in(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        llm,
        "llm_explain",
        lambda *_args: pytest.fail("Anthropic was called without consent"),
    )

    result = pipeline.review('API_KEY = "local-secret-value"')

    assert result["findings"][0]["explanation_source"] == "offline"


def test_opted_in_anthropic_receives_redacted_secret(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    sent_code = []

    def fake_llm(code, finding, evidence):
        sent_code.append(code)
        return f"Hard-coded credentials are unsafe ({evidence[0]['cwe']})."

    monkeypatch.setattr(llm, "llm_explain", fake_llm)
    result = pipeline.review(
        'API_KEY = "local-secret-value"',
        allow_external_processing=True,
    )

    assert "local-secret-value" not in sent_code[0]
    assert "<REDACTED>" in sent_code[0]
    assert result["findings"][0]["explanation_source"] == "llm"


def test_secret_is_redacted_when_explaining_a_different_finding(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    sent_code = []

    def fake_llm(code, _finding, evidence):
        sent_code.append(code)
        return f"Use the documented fix ({evidence[0]['cwe']})."

    monkeypatch.setattr(llm, "llm_explain", fake_llm)
    source = (
        'API_KEY = "local-secret-value"\n'
        'def get(cur, name):\n'
        '    cur.execute(f"SELECT * FROM users WHERE name=\'{name}\'")\n'
    )
    result = pipeline.review(source, allow_external_processing=True)

    assert any(finding["rule"] == "SQLI" for finding in result["findings"])
    assert sent_code
    assert all("local-secret-value" not in code for code in sent_code)


def test_unrelated_cwe_citation_is_rejected(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(llm, "llm_explain", lambda *_args: "This is unsafe (CWE-95).")

    result = pipeline.review(
        'def get(cur, name):\n    cur.execute(f"SELECT * FROM users WHERE name=\'{name}\'")',
        allow_external_processing=True,
    )

    assert result["findings"][0]["explanation_source"] == "offline-fallback"
    assert "CWE-89" in result["findings"][0]["explanation"]


def test_invalid_and_oversized_api_payloads_are_rejected():
    assert client.post("/review", json={"code": "  "}).status_code == 422
    assert client.post("/review", json={"code": "x" * (pipeline.MAX_CODE_CHARS + 1)}).status_code == 422


def test_syntax_error_is_returned_without_findings():
    response = client.post("/review", json={"code": "def f(:\n pass"})

    assert response.status_code == 200
    assert response.json()["syntax_error"]["line"] == 1
    assert response.json()["findings"] == []


def test_health_check():
    assert client.get("/health").json() == {"status": "ok"}
