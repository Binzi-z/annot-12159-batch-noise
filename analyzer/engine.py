"""Scan driver: file routing, module graph, fixpoint summary computation,
cross-package finding instantiation, incremental cache."""

from __future__ import annotations

import hashlib
import json
import os
import time

from .jstaint import (ModuleInfo, FuncDef, FuncAnalyzer, parser_for, MERGE_NAME)
from .model import Finding, Summary, RULES
from .pyscope import analyze_python
from .workspace import Workspace, JS_EXTS

MAX_ROUNDS = 8            # fixpoint bound — caps cross-package propagation depth
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next",
             "out", "__pycache__", ".proto-guard"}
ERROR_QUARANTINE = 3      # >N parse-error nodes -> quarantine file, don't guess


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


class Engine:
    def __init__(self, root: str, cache_path: str | None = None, full: bool = False):
        self.ws = Workspace(root)
        self.root = self.ws.root
        self.full = full
        self.cache_path = cache_path or os.path.join(self.root, ".proto-guard",
                                                     "cache.json")
        self.cache: dict = {"files": {}}
        if not full:
            self._load_cache()
        self.modules: dict[str, ModuleInfo] = {}
        self.findings: list[Finding] = []
        self.stats = {"files_js": 0, "files_py": 0, "lines": 0, "rounds": 0,
                      "reused": 0, "reanalyzed": 0, "quarantined": 0}
        self._cached_summaries: dict = {}

    # -- cache -----------------------------------------------------------------
    def _load_cache(self):
        try:
            with open(self.cache_path, encoding="utf-8") as fh:
                self.cache = json.load(fh)
        except Exception:
            self.cache = {"files": {}}

    def save_cache(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as fh:
            json.dump(self.cache, fh)

    # -- file discovery ----------------------------------------------------------
    def _files(self):
        js, py = [], []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                rel = self.ws.relpath(p)
                ext = os.path.splitext(fn)[1].lower()
                if ext in JS_EXTS and not fn.endswith(".min.js"):
                    js.append(rel)
                elif ext == ".py":
                    py.append(rel)
        return sorted(js), sorted(py)

    # -- main ---------------------------------------------------------------------
    def scan(self) -> list[Finding]:
        t0 = time.time()
        js_files, py_files = self._files()
        file_set = set(js_files)
        self.stats["files_js"] = len(js_files)
        self.stats["files_py"] = len(py_files)

        new_cache: dict[str, dict] = {}
        to_analyze = []
        for rel in js_files:
            with open(os.path.join(self.root, rel), "rb") as fh:
                data = fh.read()
            self.stats["lines"] += data.count(b"\n") + 1
            h = _sha1(data)
            cached = self.cache["files"].get(rel)
            if cached and cached.get("sha1") == h:
                new_cache[rel] = cached
                self.stats["reused"] += 1
            else:
                to_analyze.append((rel, data, h))
                self.stats["reanalyzed"] += 1

        # 1) parse + collect module symbol tables for changed files
        for rel, data, h in to_analyze:
            ext = os.path.splitext(rel)[1].lstrip(".")
            if ext in ("js", "jsx", "mjs", "cjs"):
                ext = "js"
            tree = parser_for(ext).parse(data)
            errors = sum(1 for n in _walk(tree.root_node) if n.type == "ERROR")
            if tree.root_node.has_error and errors > ERROR_QUARANTINE:
                self.stats["quarantined"] += 1
                new_cache[rel] = {"sha1": h, "quarantined": True, "summaries": {},
                                  "findings": [], "imports": []}
                continue
            mod_id = os.path.splitext(rel)[0].replace(os.sep, "/")
            mod = ModuleInfo(mod_id, rel, self.ws.package_of(rel), data, tree.root_node)
            mod.collect(lambda spec, f=rel: _strip_ext(
                self.ws.resolve(spec, f, file_set)))
            self.modules[mod_id] = mod

        # 2) fixpoint over summaries of parsed (changed) modules; unchanged
        # files contribute cached summaries via _resolve_summary.
        self._cached_summaries = {}
        for rel, entry in self.cache["files"].items():
            if rel in new_cache and entry.get("summaries"):
                mid = os.path.splitext(rel)[0].replace(os.sep, "/")
                self._cached_summaries[mid] = entry["summaries"]
        rounds = 0
        changed = True
        while changed and rounds < MAX_ROUNDS:
            changed = False
            rounds += 1
            for mod_id, mod in self.modules.items():
                for fdef in self._funcdefs(mod):
                    fa = FuncAnalyzer(mod, fdef, self._resolve_summary)
                    s = fa.run()
                    old = mod.summaries.get(fdef.name)
                    if old is None or old.to_dict() != s.to_dict():
                        changed = True
                    mod.summaries[fdef.name] = s
                    mod.__dict__.setdefault("_local_findings", {})
                    mod._local_findings[fdef.name] = [f.to_dict() for f in fa.local_findings()]
        self.stats["rounds"] = rounds

        # 3) persist fresh summaries/findings to cache
        for mod_id, mod in self.modules.items():
            rel = mod.path
            entry = new_cache.get(rel, {})
            entry["sha1"] = entry.get("sha1") or _sha1(mod.src)
            entry["summaries"] = {n: s.to_dict() for n, s in mod.summaries.items()}
            entry["findings"] = [f for lst in mod._local_findings.values() for f in lst]
            entry["imports"] = sorted({m for m, _ in mod.imports.values() if m})
            new_cache[rel] = entry

        # 4) gather findings: local (fresh or cached) + python + global call pass
        findings: list[Finding] = []
        for rel in js_files:
            entry = new_cache.get(rel)
            if not entry:
                continue
            if entry.get("quarantined"):
                findings.append(Finding(rule="META001", file=rel, line=1, col=1,
                                        pkg=self.ws.package_of(rel), severity="note",
                                        message="parse error rate above quarantine "
                                                "threshold; file skipped"))
                continue
            for fd in entry.get("findings", []):
                fd = dict(fd)
                fd.pop("fingerprint", None)
                findings.append(Finding(**fd))

        for rel in py_files:
            p = os.path.join(self.root, rel)
            with open(p, encoding="utf-8") as fh:
                src = fh.read()
            self.stats["lines"] += src.count("\n") + 1
            findings.extend(analyze_python(rel, self.ws.package_of(rel), src))

        findings.extend(self._global_call_pass(new_cache))

        # dedupe
        seen, out = set(), []
        for f in findings:
            k = (f.rule, f.file, f.line, f.col, f.message)
            if k not in seen:
                seen.add(k)
                out.append(f)
        out.sort(key=lambda f: (f.file, f.line, f.rule))
        self.findings = out
        self.cache = {"files": new_cache}
        self.save_cache()
        self.stats["seconds"] = round(time.time() - t0, 2)
        return out

    # -- helpers --------------------------------------------------------------------
    def _funcdefs(self, mod: ModuleInfo):
        out = list(mod.functions.values()) + list(mod.methods.values())
        out += mod.anonymous
        out.append(FuncDef("<module>", mod.root, [], "module"))
        return out

    def _resolve_summary(self, mod_id: str, name: str, depth: int = 0) -> Summary | None:
        if not mod_id or depth > 4:
            return None
        mod = self.modules.get(mod_id)
        if mod is None:
            # unchanged file: serve the summary from the incremental cache
            summaries = self._cached_summaries.get(mod_id, {})
            if name in summaries:
                return Summary.from_dict(summaries[name])
            return None
        local = mod.exports.get(name, name)
        s = mod.summaries.get(local)
        if s is not None:
            return s
        # re-export chain:  export { merge } from '@mono/core'
        imp = mod.imports.get(local)
        if imp and imp[0]:
            return self._resolve_summary(imp[0], imp[1] if imp[1] != "*" else local,
                                         depth + 1)
        return None

    def _global_call_pass(self, new_cache) -> list[Finding]:
        """Instantiate cross-module findings from call records with the final
        summaries. Bounded: one flat pass, no recursion — the blast radius is
        capped by MAX_ROUNDS at summary level and by this single pass here.
        Same-module calls were already reported during function analysis."""
        out = []
        for rel, entry in new_cache.items():
            if entry.get("quarantined"):
                continue
            caller_mid = os.path.splitext(rel)[0].replace(os.sep, "/")
            caller_pkg = self.ws.package_of(rel)
            for sname, sd in entry.get("summaries", {}).items():
                for call in sd.get("calls", []):
                    if call["callee_module"] == caller_mid:
                        continue  # same-module: handled during analysis
                    callee = self._summary_by_module(call["callee_module"],
                                                     call["callee_name"], new_cache)
                    if callee is None or call.get("null_proto_target"):
                        continue
                    arg_keys = call.get("arg_keys") or [[] for _ in call["arg_origins"]]
                    key_srcs = [i for i, o in enumerate(arg_keys)
                                if any(x.startswith("SRC:") for x in o)]
                    val_srcs = [i for i, o in enumerate(call["arg_origins"])
                                if any(x.startswith("SRC:") for x in o)]
                    if not key_srcs and not val_srcs:
                        continue
                    callee_pkg = self.ws.package_of(
                        self._path_of(call["callee_module"], new_cache))
                    cross = callee_pkg != caller_pkg
                    chain = f"{caller_pkg} -> {callee_pkg} ({callee['name']})"
                    if (callee.get("merge_like") or MERGE_NAME.match(callee["name"])) \
                            and not callee.get("sanitizes_keys") and key_srcs:
                        out.append(Finding(
                            rule="PP001", file=rel, line=call["line"], col=call["col"],
                            pkg=caller_pkg, severity="error", cross_pkg=cross,
                            chain=chain,
                            message=f"tainted object reaches deep-merge sink "
                                    f"'{callee['name']}()' across {chain}"))
                    for pidx, rule, _line, detail in callee.get("sink_from", []):
                        if pidx >= len(call["arg_origins"]):
                            continue
                        pool = arg_keys[pidx] if rule in ("PP001", "PP004") \
                            else call["arg_origins"][pidx]
                        if any(x.startswith("SRC:") for x in pool):
                            out.append(Finding(
                                rule=rule, file=rel, line=call["line"], col=call["col"],
                                pkg=caller_pkg,
                                severity="error" if rule != "PP002" else "warning",
                                cross_pkg=cross, chain=chain,
                                message=f"{detail} [via {callee['name']}(), {chain}]"))
        return out

    def _summary_by_module(self, mod_id, name, new_cache):
        if not mod_id:
            return None
        path = self._path_of(mod_id, new_cache)
        if path is None:
            return None
        entry = new_cache.get(path) or {}
        mod = self.modules.get(mod_id)
        if mod is not None:
            local = mod.exports.get(name, name)
            s = mod.summaries.get(local)
            if s is not None:
                return s.to_dict()
        summaries = entry.get("summaries", {})
        return summaries.get(name)

    def _path_of(self, mod_id, new_cache):
        for rel in new_cache:
            if os.path.splitext(rel)[0].replace(os.sep, "/") == mod_id:
                return rel
        return mod_id


def _strip_ext(path: str | None) -> str:
    if not path:
        return ""
    base, ext = os.path.splitext(path)
    return base if ext.lower() in JS_EXTS else path


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)
