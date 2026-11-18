"""Python-side analysis — deliberately isolated from the JS/TS engine.

Language routing is by extension only; the two engines share no symbol
tables and taint never crosses the JS<->PY boundary implicitly. Data that
moves between languages (JSON over HTTP, files, queues) re-enters as a
*source* on the receiving side, not as propagated symbols. This is what
keeps Python code from being misjudged as JS (and vice versa).
"""

from __future__ import annotations

import ast

from .model import Finding

SRC_FUNCS = ("get_json",)          # request.get_json()
SRC_ATTRS = ("json", "data", "args", "form", "values", "cookies")  # request.*
SINK_UPDATE_ATTRS = ("__dict__",)


class _PyTaint(ast.NodeVisitor):
    def __init__(self, path: str, pkg: str):
        self.path = path
        self.pkg = pkg
        self.tainted: set[str] = set()
        self.findings: list[Finding] = []

    # -- helpers -------------------------------------------------------------
    def _is_request(self, node) -> bool:
        return isinstance(node, ast.Name) and node.id in ("request", "req")

    def _is_source(self, node) -> bool:
        # request.get_json() / request.json / request.args.get(...) / json.loads(tainted)
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                if f.attr in SRC_FUNCS and self._is_request(f.value):
                    return True
                if f.attr == "loads" and isinstance(f.value, ast.Name) and f.value.id == "json":
                    return bool(node.args) and self._is_source(node.args[0])
                if f.attr == "get" and isinstance(f.value, ast.Attribute) \
                        and f.value.attr in SRC_ATTRS and self._is_request(f.value.value):
                    return True
            if isinstance(f, ast.Name) and f.id in self.tainted:
                return True
            return any(self._is_source(a) for a in node.args) and \
                isinstance(f, ast.Attribute)  # method on tainted receiver
        if isinstance(node, ast.Attribute):
            if node.attr in SRC_ATTRS and self._is_request(node.value):
                return True
            return self._is_source(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, (ast.Subscript,)):
            return self._is_source(node.value)
        if isinstance(node, ast.Dict):
            return any(self._is_source(v) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self._is_source(node.left) or self._is_source(node.right)
        return False

    # -- passes ----------------------------------------------------------------
    def visit_Assign(self, node):
        if self._is_source(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.tainted.add(tgt.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        f = node.func
        # setattr(obj, tainted_key, v)
        if isinstance(f, ast.Name) and f.id == "setattr" and len(node.args) >= 2:
            key = node.args[1]
            if (isinstance(key, ast.Name) and key.id in self.tainted) or self._is_source(key):
                self.findings.append(Finding(
                    rule="PY001", file=self.path, line=node.lineno, col=node.col_offset + 1,
                    pkg=self.pkg, severity="error",
                    message="setattr() with attacker-controlled attribute name"))
        # obj.__dict__.update(tainted) / globals().update(tainted)
        if isinstance(f, ast.Attribute) and f.attr == "update" and node.args:
            base = f.value
            is_dict_target = (isinstance(base, ast.Attribute) and base.attr == "__dict__") or \
                (isinstance(base, ast.Call) and isinstance(base.func, ast.Name)
                 and base.func.id in ("globals", "locals", "vars"))
            if is_dict_target and self._is_source(node.args[0]):
                self.findings.append(Finding(
                    rule="PY002", file=self.path, line=node.lineno, col=node.col_offset + 1,
                    pkg=self.pkg, severity="warning",
                    message="__dict__/globals().update() with tainted mapping"))
        self.generic_visit(node)


def analyze_python(path: str, pkg: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [Finding(rule="META001", file=path, line=1, col=1, pkg=pkg,
                        severity="note", message="python file failed to parse; skipped")]
    v = _PyTaint(path, pkg)
    # two passes so taint through assignments converges for straight-line code
    v.visit(tree)
    v.visit(tree)
    # dedupe
    seen, out = set(), []
    for f in v.findings:
        k = (f.rule, f.line)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
