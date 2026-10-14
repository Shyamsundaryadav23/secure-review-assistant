# SecureReview, a grounded secure code debugging and review assistant for Python

st

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.api:app --reload
```

The API is available at `http://127.0.0.1:8000`; interactive API documentation is
at `http://127.0.0.1:8000/docs`. In a second terminal, launch the UI:

```powershell
.\.venv\Scripts\python.exe -m streamlit run ui/streamlit_app.py
```

The Streamlit UI runs the review locally unless `REVIEW_API_URL` is configured. To
use the local API instead:

```powershell
$env:REVIEW_API_URL = "http://127.0.0.1:8000"
.\.venv\Scripts\python.exe -m streamlit run ui/streamlit_app.py
```

Set `USE_EMBEDDINGS=0` to use keyword retrieval without loading the local
SentenceTransformer model. With embeddings enabled, the model is downloaded/cached
by Sentence Transformers when the retriever is first initialized.

## API

`POST /review` accepts a JSON request:

```json
{
  "code": "query = f\\"SELECT * FROM users WHERE name='{name}'\\"",
  "allow_external_processing": false
}
```

The response includes findings, line numbers, severity, CWE and OWASP mappings,
retrieved evidence, retrieval hit status, suggested fixes, and total review
latency. Inputs must contain 1–100,000 characters.

Anthropic processing is **opt-in for each review**. To enable it, set
`ANTHROPIC_API_KEY` and select the consent checkbox in Streamlit or send
`"allow_external_processing": true` to the API. Detected hard-coded credential
lines are redacted before an external request. When consent is absent, no Anthropic
request is made and the grounded offline explanation is used. Code is not persisted
by the application. Do not submit source code you are not authorized to share.

## Docker Compose

```powershell
docker compose up --build
```

Open the UI at `http://localhost:8501` and the API docs at
`http://localhost:8000/docs`. The API runs as a non-root user. For offline keyword
retrieval, set `$env:USE_EMBEDDINGS = "0"` before starting Compose. The Anthropic
key is optional and should be supplied through the environment, never committed to
the repository.

## Tests and evaluation

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe evaluate.py
```

`evaluate.py` reports scanner precision/recall, CWE retrieval hit@3, and scanner
latency for the cases in `tests/cases.py`. These hand-written cases are a smoke
evaluation, not a representative benchmark or proof that code is secure. The
scanner does not currently perform interprocedural taint analysis and may miss
issues outside its rule set.
