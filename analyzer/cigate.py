"""CI gate: fail the build when a scan introduces findings that are not in
the committed baseline. Update the baseline intentionally, on main, with
`python -m analyzer gate --update`."""

from __future__ import annotations

import json
import sys


def _fingerprints_from_sarif(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    fps = set()
    for run in data.get("runs", []):
        for r in run.get("results", []):
            fp = (r.get("partialFingerprints") or {}).get("primaryLocationLineHash")
            if fp:
                fps.add(fp)
    return fps


def _load_baseline(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return set()
    return set(data.get("fingerprints", []))


def gate(sarif_path: str, baseline_path: str, update: bool = False) -> int:
    current = _fingerprints_from_sarif(sarif_path)
    if update:
        with open(baseline_path, "w", encoding="utf-8") as fh:
            json.dump({"fingerprints": sorted(current)}, fh, indent=2)
        print(f"baseline updated: {len(current)} fingerprints -> {baseline_path}")
        return 0
    baseline = _load_baseline(baseline_path)
    new = current - baseline
    if new:
        print(f"proto-guard: {len(new)} NEW finding(s) not in baseline:")
        with open(sarif_path, encoding="utf-8") as fh:
            data = json.load(fh)
        for run in data.get("runs", []):
            for r in run.get("results", []):
                fp = (r.get("partialFingerprints") or {}).get("primaryLocationLineHash")
                if fp in new:
                    loc = r["locations"][0]["physicalLocation"]
                    print(f"  [{r['ruleId']}] {loc['artifactLocation']['uri']}:"
                          f"{loc['region']['startLine']}  {r['message']['text']}")
        print("Fix the finding, or regenerate the baseline on main with "
              "`python -m analyzer gate --update`.")
        return 1
    print(f"proto-guard: OK ({len(current)} findings, all in baseline)")
    return 0
