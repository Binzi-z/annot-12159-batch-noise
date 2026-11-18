"""Performance acceptance: synthetic 200k-line monorepo.

  python scripts/bench.py            # generate + full scan + incremental scan

Thresholds: full scan < 180 s, incremental (3 changed files) < 15 s.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.engine import Engine  # noqa: E402

PACKAGES = 40
FILES_PER_PKG = 25
LINES_PER_FILE = 200          # 40 * 25 * 200 = 200,000 lines
FULL_BUDGET_S = 180
INCR_BUDGET_S = 15

SAFE_FN = """\
export function compute{fi}_{i}(input) {{
  // {pad}
  const acc = {{}};
  for (const k of Object.keys(OPTIONS)) {{
    if (!ALLOWED.includes(k)) continue;
    acc[k] = OPTIONS[k];
  }}
  return acc.valueOf();
}}
"""

TAINTED_FN = """\
import {{ merge }} from '@bench/pkg{dep}';
export function handle{fi}(req, res) {{
  const cfg = merge({{}}, req.body);
  return res.send(cfg);
}}
"""

MERGE_LIB = """\
export function merge(target, source) {
  for (const k in source) {
    if (source[k] && typeof source[k] === 'object') {
      target[k] = merge(target[k] || {}, source[k]);
    } else {
      target[k] = source[k];
    }
  }
  return target;
}
"""


def gen_repo(root: str) -> int:
    rng = random.Random(42)
    total_lines = 0
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "package.json"), "w") as fh:
        fh.write('{ "name": "bench", "workspaces": ["packages/*"] }')
    for p in range(PACKAGES):
        pdir = os.path.join(root, "packages", f"pkg{p}")
        os.makedirs(os.path.join(pdir, "src"))
        with open(os.path.join(pdir, "package.json"), "w") as fh:
            fh.write(f'{{ "name": "@bench/pkg{p}", "main": "src/index.js" }}')
        with open(os.path.join(pdir, "src", "index.js"), "w") as fh:
            fh.write(MERGE_LIB)
            total_lines += MERGE_LIB.count("\n") + 1
        for f in range(FILES_PER_PKG):
            chunks = ["const OPTIONS = { a: 1 };\nconst ALLOWED = ['a'];\n"]
            for i in range(LINES_PER_FILE // 10):
                dep = rng.randrange(PACKAGES)
                chunks.append(SAFE_FN.format(fi=f, i=i, pad="x" * 40))
            if f % 8 == 0:  # a few tainted call sites, cross-package
                chunks.append(TAINTED_FN.format(fi=f, dep=(p + 1) % PACKAGES))
            text = "\n".join(chunks)
            total_lines += text.count("\n") + 1
            with open(os.path.join(pdir, "src", f"mod{f}.js"), "w") as fh:
                fh.write(text)
    return total_lines


def main() -> int:
    work = tempfile.mkdtemp(prefix="pp-bench-")
    repo = os.path.join(work, "repo")
    lines = gen_repo(repo)
    print(f"generated {lines:,} lines in {repo}")

    t0 = time.time()
    eng = Engine(repo, full=True)
    findings = eng.scan()
    full_s = time.time() - t0
    print(f"FULL        : {full_s:6.1f}s  ({len(findings)} findings, "
          f"{eng.stats['files_js']} js files, budget {FULL_BUDGET_S}s)")

    # incremental: touch 3 files
    for p in (0, 1, 2):
        path = os.path.join(repo, "packages", f"pkg{p}", "src", "mod0.js")
        with open(path, "a") as fh:
            fh.write("\n// touched\n")
    t0 = time.time()
    eng2 = Engine(repo)  # incremental: reuses .proto-guard cache
    findings2 = eng2.scan()
    incr_s = time.time() - t0
    print(f"INCREMENTAL : {incr_s:6.1f}s  ({len(findings2)} findings, "
          f"reanalyzed={eng2.stats['reanalyzed']} reused={eng2.stats['reused']}, "
          f"budget {INCR_BUDGET_S}s)")

    ok = full_s < FULL_BUDGET_S and incr_s < INCR_BUDGET_S
    print("BENCH:", "PASS" if ok else "FAIL")
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
