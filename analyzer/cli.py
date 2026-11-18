"""CLI:  python -m analyzer scan <repo> [--sarif out.sarif] [--full]
        python -m analyzer gate --sarif out.sarif --baseline ci/baseline.json [--update]
"""

from __future__ import annotations

import argparse
import json
import sys

from .cigate import gate
from .engine import Engine
from .sarif import to_sarif


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="proto-guard")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan a repository")
    sp.add_argument("root")
    sp.add_argument("--sarif", help="write SARIF to this path")
    sp.add_argument("--full", action="store_true", help="ignore incremental cache")
    sp.add_argument("--cache", help="cache file path")

    gp = sub.add_parser("gate", help="compare SARIF against baseline (CI)")
    gp.add_argument("--sarif", required=True)
    gp.add_argument("--baseline", required=True)
    gp.add_argument("--update", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        eng = Engine(args.root, cache_path=args.cache, full=args.full)
        findings = eng.scan()
        sarif = to_sarif(findings)
        if args.sarif:
            with open(args.sarif, "w", encoding="utf-8") as fh:
                json.dump(sarif, fh, indent=2)
        by_rule = {}
        for f in findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        print(f"proto-guard: {len(findings)} findings "
              f"({', '.join(f'{k}:{v}' for k, v in sorted(by_rule.items())) or 'clean'})")
        print(f"stats: {json.dumps(eng.stats)}")
        if args.sarif:
            print(f"sarif -> {args.sarif}")
        return 0

    if args.cmd == "gate":
        return gate(args.sarif, args.baseline, update=args.update)
    return 2


if __name__ == "__main__":
    sys.exit(main())
