"""Shared data model: taint values, findings, function summaries, rules."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict


# ---------------------------------------------------------------------------
# Taint value
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class T:
    """Taint of a value.

    origins:     where the *value* may come from ("SRC:*" concrete sources,
                 "P<n>" symbolic parameter of the function under analysis).
    key_origins: origins controlling the *keys* of an object (attacker can
                 choose property names, e.g. a parsed JSON body).
    from_json:   value came straight out of JSON.parse of a tainted string.
    """

    origins: frozenset = frozenset()
    key_origins: frozenset = frozenset()
    from_json: bool = False

    def union(self, other: "T") -> "T":
        return T(
            self.origins | other.origins,
            self.key_origins | other.key_origins,
            self.from_json or other.from_json,
        )

    @property
    def tainted(self) -> bool:
        return bool(self.origins or self.key_origins)

    @property
    def src_origins(self) -> frozenset:
        return frozenset(o for o in (self.origins | self.key_origins) if o.startswith("SRC:"))

    @property
    def param_origins(self) -> frozenset:
        return frozenset(o for o in (self.origins | self.key_origins) if o.startswith("P"))


CLEAN = T()

SRC_HTTP = "SRC:http"        # request body / query string / params
SRC_QUERY = "SRC:query"      # location.search / URLSearchParams
SRC_LS = "SRC:localStorage"  # localStorage / sessionStorage

# ---------------------------------------------------------------------------
# Rules (all implemented from scratch in this package)
# ---------------------------------------------------------------------------
RULES = {
    "PP001": {"name": "tainted-deep-merge",
              "desc": "attacker-controlled object reaches a deep-merge/extend sink",
              "level": "error"},
    "PP002": {"name": "tainted-object-assign",
              "desc": "Object.assign copies attacker-controlled source object",
              "level": "warning"},
    "PP003": {"name": "json-parse-direct-assign",
              "desc": "JSON.parse result of tainted input assigned/merged directly",
              "level": "error"},
    "PP004": {"name": "dynamic-key-write",
              "desc": "computed property write with attacker-controlled key",
              "level": "error"},
    "PP005": {"name": "proto-key-access",
              "desc": "explicit __proto__/constructor/prototype key access",
              "level": "error"},
    "PY001": {"name": "py-dynamic-attr-write",
              "desc": "setattr() with attacker-controlled attribute name (python)",
              "level": "error"},
    "PY002": {"name": "py-dict-update-tainted",
              "desc": "__dict__.update/globals().update with tainted mapping (python)",
              "level": "warning"},
    "META001": {"name": "unparsed-file",
                "desc": "file skipped: parse error rate above quarantine threshold",
                "level": "note"},
}

DANGEROUS_KEYS = ("__proto__", "constructor", "prototype")


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    rule: str
    file: str          # repo-relative, posix
    line: int
    col: int
    pkg: str
    message: str
    severity: str = "error"
    cross_pkg: bool = False
    chain: str = ""    # e.g. "web@app -> core@utils (merge)"

    def fingerprint(self) -> str:
        h = hashlib.sha1()
        h.update(f"{self.rule}|{self.file}|{self.line}|{self.message}".encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


# ---------------------------------------------------------------------------
# Function summary (unit of cross-file / cross-package propagation)
# ---------------------------------------------------------------------------
@dataclass
class CallRecord:
    """A call site inside a function, with the taint of its arguments."""
    callee_module: str       # resolved module id or "" (unresolved)
    callee_name: str
    arg_origins: list        # list[list[str]] value origins per argument
    arg_keys: list           # list[list[str]] key-control origins per argument
    line: int
    col: int
    null_proto_target: bool = False


@dataclass
class Summary:
    module: str
    name: str
    params: list = field(default_factory=list)
    ret_from: list = field(default_factory=list)        # param idxs flowing to return
    sink_from: list = field(default_factory=list)       # [param_idx, rule, line, detail]
    merge_like: bool = False
    sanitizes_keys: bool = False
    calls: list = field(default_factory=list)           # list[CallRecord-as-dict]
    findings: list = field(default_factory=list)        # local findings (dicts)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Summary":
        return Summary(**d)
