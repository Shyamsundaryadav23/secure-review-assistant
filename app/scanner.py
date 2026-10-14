"""Deterministic scanner: Python ast + regex rules. Never executes the submitted code."""
import ast, re

SEVERITY = {"SQLI": "High", "SECRET": "High", "EVAL": "High", "CMDI": "High", "PICKLE": "High",
            "YAML": "High", "WEAKHASH": "Medium", "TLS": "High", "DEBUG": "Medium"}
SECRET_RE = re.compile(r"(?i)(password|passwd|secret|api_?key|token)\w*\s*=\s*['\"][^'\"]{4,}['\"]")


def _name(n):
    if isinstance(n, ast.Attribute):
        return _name(n.value) + "." + n.attr
    return n.id if isinstance(n, ast.Name) else ""


def _dynamic(n):
    return isinstance(n, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(n, ast.Call) and _name(n.func).endswith(".format"))


def scan(code):
    """Return (findings, syntax_error). Each finding: rule, line, severity, why."""
    out = []

    def add(rule, line, why):
        out.append({"rule": rule, "line": line, "severity": SEVERITY[rule], "why": why})

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [], {"line": e.lineno, "msg": e.msg}
    for i, l in enumerate(code.splitlines(), 1):
        if SECRET_RE.search(l):
            add("SECRET", i, "Hard-coded credential literal")
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f, ln = _name(n.func), n.lineno
        kw = {k.arg: k.value for k in n.keywords}
        isconst = lambda k, v: isinstance(kw.get(k), ast.Constant) and kw[k].value is v
        if f.endswith(".execute") and n.args and _dynamic(n.args[0]):
            add("SQLI", ln, "SQL built by string formatting/concatenation")
        elif f in ("eval", "exec"):
            add("EVAL", ln, f + "() call")
        elif f == "os.system" or (f.startswith("subprocess.") and isconst("shell", True)):
            add("CMDI", ln, "Shell command execution")
        elif f in ("pickle.loads", "pickle.load"):
            add("PICKLE", ln, "Unsafe deserialisation")
        elif f in ("hashlib.md5", "hashlib.sha1"):
            add("WEAKHASH", ln, f + " is a weak hash")
        elif f.startswith("requests.") and isconst("verify", False):
            add("TLS", ln, "TLS verification disabled")
        elif f == "yaml.load" and "Loader" not in kw:
            add("YAML", ln, "yaml.load without safe Loader")
        elif f.endswith(".run") and isconst("debug", True):
            add("DEBUG", ln, "Debug mode enabled")
    return sorted(out, key=lambda r: r["line"]), None
