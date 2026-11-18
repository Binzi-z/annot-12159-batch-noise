"""Acceptance test: run the analyzer over the 50-case corpus and check
recall >= 85% on positives and false-positive rate <= 15% on negatives."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.engine import Engine  # noqa: E402
from cases import CASES  # noqa: E402


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    out = {}
    for case in CASES:
        root = tmp_path_factory.mktemp(case["id"])
        for rel, content in case["files"].items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        eng = Engine(str(root), full=True)
        findings = eng.scan()
        out[case["id"]] = {
            "case": case,
            "rules": [f.rule for f in findings],
            "findings": [(f.rule, f.file, f.line, f.message) for f in findings],
        }
    return out


def test_corpus_size():
    assert len(CASES) == 50
    pos = [c for c in CASES if c["expect"]]
    neg = [c for c in CASES if not c["expect"]]
    assert len(pos) >= 25 and len(neg) >= 15


def test_each_positive_case(results):
    misses = []
    for cid, r in results.items():
        expect = r["case"]["expect"]
        if not expect:
            continue
        for rule in expect:
            if rule not in r["rules"]:
                misses.append((cid, rule, r["findings"]))
    assert not misses, f"missing expected findings: {misses}"


def test_each_negative_case(results):
    fps = []
    for cid, r in results.items():
        if r["case"]["expect"]:
            continue
        if r["rules"]:
            fps.append((cid, r["findings"]))
    assert not fps, f"false positives: {fps}"


def test_acceptance_thresholds(results):
    pos = [r for r in results.values() if r["case"]["expect"]]
    neg = [r for r in results.values() if not r["case"]["expect"]]
    tp = sum(1 for r in pos if all(rule in r["rules"] for rule in r["case"]["expect"]))
    fp = sum(1 for r in neg if r["rules"])
    recall = tp / len(pos)
    fp_rate = fp / len(neg)
    print(f"\nrecall={recall:.2%} ({tp}/{len(pos)})  fp_rate={fp_rate:.2%} ({fp}/{len(neg)})")
    assert recall >= 0.85, f"recall {recall:.2%} < 85%"
    assert fp_rate <= 0.15, f"false-positive rate {fp_rate:.2%} > 15%"


def test_sarif_shape(results, tmp_path):
    from analyzer.sarif import to_sarif
    from analyzer.model import Finding
    sarif = to_sarif([Finding(rule="PP001", file="a/b.js", line=3, col=5,
                              pkg="x", message="m")])
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"]
    res = run["results"][0]
    assert res["ruleId"] == "PP001"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert res["partialFingerprints"]["primaryLocationLineHash"]
    json.dumps(sarif)  # must be serialisable
