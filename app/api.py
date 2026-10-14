from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from .pipeline import MAX_CODE_CHARS, review

app = FastAPI(
    title="Secure Code Review Assistant",
    description=(
        "Deterministic Python security scanning with CWE/OWASP-grounded explanations. "
        "Submitted code is processed in memory. Anthropic processing is opt-in per request."
    ),
    version="1.0.0",
)


class Req(BaseModel):
    code: str = Field(min_length=1, max_length=MAX_CODE_CHARS)
    allow_external_processing: bool = False

    @field_validator("code")
    @classmethod
    def code_must_not_be_blank(cls, value):
        if not value.strip():
            raise ValueError("Code must contain at least one non-whitespace character.")
        return value


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/review")
def review_endpoint(req: Req):
    return review(req.code, allow_external_processing=req.allow_external_processing)
