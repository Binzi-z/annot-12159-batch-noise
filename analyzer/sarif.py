"""SARIF 2.1.0 emission."""

from __future__ import annotations

from .model import RULES
from . import __version__


def to_sarif(findings, root_uri: str = "") -> dict:
    rules = [{
        "id": rid,
        "name": meta["name"],
        "shortDescription": {"text": meta["desc"]},
        "defaultConfiguration": {"level": meta["level"]},
        "properties": {"security-severity": "8.0" if meta["level"] == "error" else "5.0"},
    } for rid, meta in RULES.items()]

    results = []
    for f in findings:
        msg = f.message
        if f.cross_pkg:
            msg += f"  [cross-package chain: {f.chain}]"
        results.append({
            "ruleId": f.rule,
            "level": RULES.get(f.rule, {}).get("level", "warning"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file.replace("\\", "/"),
                        "uriBaseId": "SRCROOT",
                    },
                    "region": {"startLine": f.line, "startColumn": max(f.col, 1)},
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint()},
            "properties": {"package": f.pkg, "crossPackage": f.cross_pkg},
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "proto-guard",
                    "version": __version__,
                    "informationUri": "https://example.invalid/proto-guard",
                    "rules": rules,
                }
            },
            "originalUriBaseIds": {"SRCROOT": {"uri": root_uri or "file:///"}},
            "results": results,
        }],
    }
