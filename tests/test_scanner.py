import pytest
from app.scanner import scan
from tests.cases import CASES


@pytest.mark.parametrize("name,code,expected", CASES)
def test_case(name, code, expected):
    findings, err = scan(code)
    assert err is None
    assert {f["rule"] for f in findings} == expected


def test_syntax_error():
    findings, err = scan("def f(:\n  pass")
    assert err is not None and findings == []
