"""Workspace model: package.json workspaces, tsconfig path aliases, import
resolution. This is what lets taint cross package boundaries in a monorepo."""

from __future__ import annotations

import glob
import json
import os
import re

JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


def _load_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.loads(_strip_jsonc(fh.read()))
    except Exception:
        return None


class Package:
    def __init__(self, name: str, dir_rel: str, main_rel: str):
        self.name = name
        self.dir = dir_rel          # repo-relative posix dir
        self.main = main_rel        # repo-relative posix entry file (no ext maybe)


class Workspace:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.packages: dict[str, Package] = {}
        self.tsconfigs: list[dict] = []   # {dir, base_url, paths}
        self._discover()

    # -- discovery ---------------------------------------------------------
    def _discover(self):
        root_pkg = _load_json(os.path.join(self.root, "package.json")) or {}
        ws = root_pkg.get("workspaces") or []
        if isinstance(ws, dict):
            ws = ws.get("packages") or []
        dirs: list[str] = []
        for pattern in ws:
            for p in glob.glob(os.path.join(self.root, pattern.replace("/", os.sep))):
                if os.path.isdir(p):
                    dirs.append(os.path.relpath(p, self.root))
        if not dirs:
            # single-package repo: root itself is the package
            dirs = ["."]
        for d in dirs:
            pkg_json = _load_json(os.path.join(self.root, d, "package.json")) or {}
            name = pkg_json.get("name")
            if not name and d == ".":
                name = root_pkg.get("name")
            if not name:
                name = os.path.basename(os.path.normpath(d)) if d != "." else "<root>"
            main = pkg_json.get("module") or pkg_json.get("main") or "index.js"
            self.packages[name] = Package(name, d.replace(os.sep, "/"),
                                          os.path.join(d, main).replace(os.sep, "/"))
        # tsconfigs anywhere in the repo (nearest one wins per file)
        for path in glob.glob(os.path.join(self.root, "**", "tsconfig*.json"), recursive=True):
            if "node_modules" in path:
                continue
            cfg = _load_json(path)
            if not cfg:
                continue
            co = cfg.get("compilerOptions") or {}
            base = co.get("baseUrl") or "."
            self.tsconfigs.append({
                "dir": os.path.dirname(os.path.relpath(path, self.root)).replace(os.sep, "/"),
                "base_url": base,
                "paths": co.get("paths") or {},
            })

    # -- helpers ------------------------------------------------------------
    def relpath(self, path: str) -> str:
        return os.path.relpath(path, self.root).replace(os.sep, "/")

    def package_of(self, rel_file: str) -> str:
        best, best_len = "<root>", -1
        for pkg in self.packages.values():
            d = pkg.dir
            if d == ".":
                continue
            if rel_file == d or rel_file.startswith(d + "/"):
                if len(d) > best_len:
                    best, best_len = pkg.name, len(d)
        return best

    def _candidate(self, noext: str, files: set) -> str | None:
        for ext in JS_EXTS:
            if noext + ext in files:
                return noext + ext
        if noext in files and noext.endswith(JS_EXTS):
            return noext
        for ext in JS_EXTS:
            if noext + "/index" + ext in files:
                return noext + "/index" + ext
        return None

    def _tsconfig_for(self, rel_file: str) -> dict | None:
        best, best_len = None, -1
        for tc in self.tsconfigs:
            d = tc["dir"]
            if d == "." or rel_file.startswith(d + "/"):
                if len(d) > best_len:
                    best, best_len = tc, len(d)
        return best

    # -- import resolution ---------------------------------------------------
    def resolve(self, spec: str, from_file: str, files: set) -> str | None:
        """Resolve an import specifier to a repo-relative module path, or None
        for external (npm) modules — those stay opaque blast-radius boundaries."""
        from_dir = os.path.dirname(from_file)
        if spec.startswith("."):
            joined = os.path.normpath(os.path.join(from_dir, spec)).replace(os.sep, "/")
            return self._candidate(joined, files)
        # tsconfig paths aliases
        tc = self._tsconfig_for(from_file)
        if tc:
            for pat, targets in (tc["paths"] or {}).items():
                star = "*" in pat
                prefix = pat[:-1] if star else pat
                if spec == pat or (star and spec.startswith(prefix)):
                    rest = spec[len(prefix):] if star else ""
                    for tgt in targets:
                        t = tgt.replace("*", rest)
                        base = tc["base_url"].rstrip("/")
                        joined = os.path.normpath(
                            os.path.join(tc["dir"], base, t)).replace(os.sep, "/")
                        hit = self._candidate(joined, files)
                        if hit:
                            return hit
            # baseUrl fallback
            joined = os.path.normpath(
                os.path.join(tc["dir"], tc["base_url"], spec)).replace(os.sep, "/")
            hit = self._candidate(joined, files)
            if hit:
                return hit
        # workspace package name (exact or subpath)
        for name, pkg in sorted(self.packages.items(), key=lambda kv: -len(kv[0])):
            if spec == name or spec.startswith(name + "/"):
                sub = spec[len(name):].lstrip("/")
                target = os.path.join(pkg.dir, sub).replace(os.sep, "/") if sub else pkg.main
                hit = self._candidate(os.path.normpath(target).replace(os.sep, "/"), files)
                if hit:
                    return hit
        return None  # external dependency: opaque
