"""JS/TS taint engine: tree-sitter syntax + self-built symbol tables.

Per module we collect imports/exports/functions (module symbol table), then
run an abstract interpretation per function producing a *summary*. Summaries
are the only thing that crosses file/package boundaries, which is what keeps
the cross-package blast radius bounded (see docs/analyzer-design.md).
"""

from __future__ import annotations

import re

from tree_sitter_language_pack import get_parser

from .model import (T, CLEAN, Finding, Summary, CallRecord,
                    SRC_HTTP, SRC_QUERY, SRC_LS, DANGEROUS_KEYS)

_PARSERS = {}


def parser_for(ext: str):
    lang = {"ts": "typescript", "tsx": "tsx"}.get(ext, "javascript")
    if lang not in _PARSERS:
        _PARSERS[lang] = get_parser(lang)
    return _PARSERS[lang]


MERGE_NAME = re.compile(
    r"^(deep_?merge|merge_?deep|merge|extend(_?deep)?|defaults(_?deep)?|"
    r"assign_?in|mixin|deep_?extend|deep_?assign|deep_?copy|merge_?options)$", re.I)

REQ_OBJ_RE = re.compile(
    r"^(req|request|ctx\.req|ctx\.request|event|e)\."
    r"(body|query|params|headers|cookies)(\..*)?$")
QUERY_RE = re.compile(r"^(window\.)?location\.(search|hash|href)$")

FUNC_TYPES = ("function_declaration", "function_expression", "arrow_function",
              "generator_function_declaration", "generator_function")
EXIT_TYPES = ("return_statement", "break_statement", "continue_statement",
              "throw_statement")


def text_of(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def dotted(node, src: bytes) -> str | None:
    """'a.b.c' for pure member chains, else None."""
    parts = []
    n = node
    while n is not None and n.type == "member_expression":
        prop = n.child_by_field_name("property")
        if prop is None:
            return None
        parts.append(text_of(prop, src))
        n = n.child_by_field_name("object")
    if n is None or n.type != "identifier":
        return None
    parts.append(text_of(n, src))
    return ".".join(reversed(parts))


def _iter_nodes(node):
    yield node
    for c in node.children:
        yield from _iter_nodes(c)


class FuncDef:
    def __init__(self, name, node, params, kind):
        self.name = name
        self.node = node
        self.params = params
        self.kind = kind  # "function" | "method" | "module"


# ---------------------------------------------------------------------------
# Module symbol table
# ---------------------------------------------------------------------------
class ModuleInfo:
    def __init__(self, module_id: str, path: str, pkg: str, src: bytes, root_node):
        self.id = module_id
        self.path = path
        self.pkg = pkg
        self.src = src
        self.root = root_node
        self.imports: dict[str, tuple[str, str]] = {}   # local -> (module, name|"*")
        self.exports: dict[str, str] = {}               # exported -> local
        self.functions: dict[str, FuncDef] = {}
        self.methods: dict[str, FuncDef] = {}
        self.anonymous: list[FuncDef] = []              # express-style handlers etc.
        self.summaries: dict[str, Summary] = {}

    # -- collection ---------------------------------------------------------
    def collect(self, resolve):
        for node in self.root.children:
            self._collect_top(node, resolve, exported=False)
        # class methods (one level)
        for node in _iter_nodes(self.root):
            if node.type in ("class_declaration", "class"):
                body = node.child_by_field_name("body")
                if body:
                    for m in body.named_children:
                        if m.type in ("method_definition", "method_signature"):
                            name_node = m.child_by_field_name("name")
                            fn = m  # method node itself has params/body fields
                            if name_node:
                                name = text_of(name_node, self.src)
                                self.methods.setdefault(
                                    name, FuncDef(name, fn, _params_of(fn, self.src), "method"))
        # anonymous arrows/functions (express handlers, promise callbacks):
        # analysed as their own units so sinks inside them are still seen.
        named_fn_nodes = {id(fd.node) for fd in self.functions.values()}
        for node in _iter_nodes(self.root):
            if node.type in ("arrow_function", "function_expression") \
                    and id(node) not in named_fn_nodes:
                if node.parent is not None and node.parent.type == "variable_declarator":
                    continue
                self.anonymous.append(FuncDef(f"<anon:{node.start_point[0] + 1}>",
                                              node, _params_of(node, self.src), "function"))

    def _collect_top(self, node, resolve, exported):
        n = node
        is_exported = exported
        if n.type == "export_statement":
            decl = n.child_by_field_name("declaration")
            if decl is not None:
                for name in self._declared_names(decl):
                    self.exports[name] = name
                self._collect_top(decl, resolve, exported=True)
            else:
                # export { a, b as c }            — plain
                # export { a } from './mod'       — re-export: follow it
                src_node = n.child_by_field_name("source")
                mod = ""
                if src_node is not None:
                    mod = resolve(text_of(src_node, self.src).strip("'\"")) or ""
                for c in _iter_nodes(n):
                    if c.type == "export_specifier":
                        local = text_of(c.child_by_field_name("name"), self.src)
                        alias = c.child_by_field_name("alias")
                        exported = text_of(alias, self.src) if alias else local
                        self.exports[exported] = local
                        if mod:
                            self.imports[local] = (mod, local)
            return
        if n.type == "import_statement":
            source = n.child_by_field_name("source")
            if source is None:
                return
            spec = text_of(source, self.src).strip("'\"")
            mod = resolve(spec) or ""
            for c in _iter_nodes(n):
                if c.type == "import_specifier":
                    imported = text_of(c.child_by_field_name("name"), self.src)
                    alias = c.child_by_field_name("alias")
                    self.imports[text_of(alias, self.src) if alias else imported] = (mod, imported)
                elif c.type == "namespace_import":
                    ident = next((x for x in c.named_children if x.type == "identifier"), None)
                    if ident is not None:
                        self.imports[text_of(ident, self.src)] = (mod, "*")
                elif c.type == "identifier" and c.parent.type == "import_clause":
                    self.imports[text_of(c, self.src)] = (mod, "default")
            return
        if n.type in ("lexical_declaration", "variable_declaration"):
            for d in n.named_children:
                if d.type == "variable_declarator":
                    name_node = d.child_by_field_name("name")
                    value = d.child_by_field_name("value")
                    if name_node is None or name_node.type != "identifier":
                        continue
                    name = text_of(name_node, self.src)
                    if value is not None and value.type in FUNC_TYPES:
                        self.functions[name] = FuncDef(name, value, _params_of(value, self.src),
                                                       "function")
                    elif value is not None and value.type == "call_expression":
                        self._maybe_require(name, value, resolve)
            return
        if n.type in ("function_declaration", "generator_function_declaration"):
            name_node = n.child_by_field_name("name")
            if name_node is not None:
                name = text_of(name_node, self.src)
                self.functions[name] = FuncDef(name, n, _params_of(n, self.src), "function")
            return

    def _maybe_require(self, name, call, resolve):
        fn = call.child_by_field_name("function")
        if fn is None or text_of(fn, self.src) != "require":
            return
        args = call.child_by_field_name("arguments")
        if args is None or not args.named_children:
            return
        spec = text_of(args.named_children[0], self.src).strip("'\"")
        mod = resolve(spec) or ""
        self.imports[name] = (mod, "*")

    def _declared_names(self, decl):
        names = []
        if decl.type in ("function_declaration", "generator_function_declaration",
                         "class_declaration"):
            nm = decl.child_by_field_name("name")
            if nm is not None:
                names.append(text_of(nm, self.src))
        elif decl.type in ("lexical_declaration", "variable_declaration"):
            for d in decl.named_children:
                if d.type == "variable_declarator":
                    nm = d.child_by_field_name("name")
                    if nm is not None and nm.type == "identifier":
                        names.append(text_of(nm, self.src))
        return names


def _params_of(fn_node, src) -> list[str]:
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        # arrow with single bare param:  x => ...
        for c in fn_node.children:
            if c.type == "identifier":
                return [text_of(c, src)]
        return []
    out = []
    for p in params.named_children:
        if p.type == "identifier":
            out.append(text_of(p, src))
        elif p.type in ("required_parameter", "optional_parameter"):
            pat = p.child_by_field_name("pattern")
            if pat is not None and pat.type == "identifier":
                out.append(text_of(pat, src))
            else:
                out.append("_")
        elif p.type in ("assignment_pattern",):
            left = p.child_by_field_name("left")
            out.append(text_of(left, src) if left is not None and left.type == "identifier"
                       else "_")
        else:
            out.append("_")
    return out


# ---------------------------------------------------------------------------
# Function analysis
# ---------------------------------------------------------------------------
class FuncAnalyzer:
    def __init__(self, mod: ModuleInfo, fdef: FuncDef, resolve_summary):
        self.mod = mod
        self.src = mod.src
        self.fdef = fdef
        self.resolve_summary = resolve_summary  # (module, name) -> Summary|None
        self.env: dict[str, T] = {}
        self.guarded_keys: set[str] = set()
        self.sink_events: list[tuple[str, frozenset, int, int, str]] = []
        self.calls: list[CallRecord] = []
        self.ret_taint = CLEAN
        self.recursive = False
        self.has_key_loop = False
        self.has_dynamic_write = False

    # -- entry ---------------------------------------------------------------
    def run(self) -> Summary:
        for i, p in enumerate(self.fdef.params):
            self.env[p] = T(frozenset({f"P{i}"}))
            if p in ("req", "request", "ctx"):
                self.env[p] = T(frozenset({f"P{i}", SRC_HTTP}))
        body = self.fdef.node.child_by_field_name("body")
        if body is not None:
            self._scan_guards(body)
            if body.type == "statement_block":
                self._exec_block(body)
            else:
                # arrow with expression body:  () => expr  (implicit return)
                self.ret_taint = self.ret_taint.union(self._eval(body))
        summary = Summary(module=self.mod.id, name=self.fdef.name,
                          params=list(self.fdef.params))
        for o in self.ret_taint.origins | self.ret_taint.key_origins:
            if o.startswith("P") and o[1:].isdigit():
                summary.ret_from.append(int(o[1:]))
        for rule, origins, line, col, detail in self.sink_events:
            for o in origins:
                if o.startswith("P") and o[1:].isdigit():
                    summary.sink_from.append([int(o[1:]), rule, line, detail])
        summary.merge_like = (self.has_key_loop and self.has_dynamic_write) or self.recursive
        summary.sanitizes_keys = bool(self.guarded_keys)
        summary.calls = [c.__dict__ for c in self.calls]
        return summary

    def local_findings(self) -> list[Finding]:
        out = []
        for rule, origins, line, col, detail in self.sink_events:
            if any(o.startswith("SRC:") for o in origins):
                out.append(Finding(rule=rule, file=self.mod.path, line=line, col=col,
                                   pkg=self.mod.pkg, message=detail,
                                   severity="error" if rule in ("PP001", "PP003", "PP004", "PP005")
                                   else "warning"))
        return out

    # -- sanitizer pre-scan ----------------------------------------------------
    def _scan_guards(self, body):
        """Recognise hasOwnProperty / key blacklist / key whitelist guards and
        mark the guarded key variable as sanitised (flow-insensitive within the
        function — documented limitation)."""
        for node in _iter_nodes(body):
            if node.type != "if_statement":
                continue
            cond = node.child_by_field_name("condition")
            cons = node.child_by_field_name("consequence")
            if cond is None:
                continue
            cond_text = text_of(cond, self.src)
            exits = cons is not None and any(
                n.type in EXIT_TYPES for n in _iter_nodes(cons))
            key_vars = set()
            # hasOwnProperty guard: both `if (has(k)) write` and
            # `if (!has(k)) continue` forms sanitise the key.
            if "hasOwnProperty" in cond_text:
                key_vars |= _call_arg_idents(cond, self.src)
            # whitelist: allowed.includes(k) / indexOf(k), either branch form
            if ".includes(" in cond_text or ".indexOf(" in cond_text:
                key_vars |= _call_arg_idents(cond, self.src)
            # blacklist of dangerous keys: only when the guard bails out
            if exits and any(k in cond_text for k in DANGEROUS_KEYS):
                key_vars |= _compared_idents(cond, self.src)
            self.guarded_keys |= key_vars

    # -- statements ------------------------------------------------------------
    def _exec_block(self, node):
        for st in node.named_children:
            self._exec(st)

    def _exec(self, node):
        t = node.type
        if t in ("lexical_declaration", "variable_declaration"):
            for d in node.named_children:
                if d.type == "variable_declarator":
                    self._declare(d)
        elif t == "expression_statement":
            self._eval(node.named_children[0]) if node.named_children else None
        elif t == "assignment_expression":
            self._assign(node)
        elif t == "if_statement":
            self._exec_if(node)
        elif t in ("for_in_statement", "for_of_statement"):
            self._exec_for_in_of(node)
        elif t == "for_statement":
            for f in ("initializer", "condition", "increment"):
                c = node.child_by_field_name(f)
                if c is not None:
                    self._exec(c) if c.type not in ("binary_expression",) else self._eval(c)
            body = node.child_by_field_name("body")
            if body is not None:
                self._exec(body)
        elif t in ("while_statement", "do_statement"):
            body = node.child_by_field_name("body")
            cond = node.child_by_field_name("condition")
            if cond is not None:
                self._eval(cond)
            if body is not None:
                self._exec(body)
        elif t == "return_statement":
            if node.named_children:
                self.ret_taint = self.ret_taint.union(self._eval(node.named_children[0]))
        elif t == "try_statement":
            for f in ("body", "handler", "finalizer"):
                c = node.child_by_field_name(f)
                if c is not None:
                    self._exec(c)
        elif t == "switch_statement":
            for c in node.named_children:
                if c.type == "switch_body":
                    self._exec_block(c)
        elif t == "statement_block":
            self._exec_block(node)
        elif t == "export_statement":
            decl = node.child_by_field_name("declaration")
            if decl is not None:
                self._exec(decl)
        elif t in ("function_declaration", "class_declaration"):
            pass  # declarations handled by the module symbol table
        else:
            for c in node.named_children:
                self._exec(c)

    def _declare(self, d):
        name_node = d.child_by_field_name("name")
        value = d.child_by_field_name("value")
        if name_node is None:
            return
        tv = self._eval(value) if value is not None else CLEAN
        if name_node.type == "identifier":
            self.env[text_of(name_node, self.src)] = tv
        elif name_node.type == "object_pattern":
            # const {a, b} = tainted
            for prop in _iter_nodes(name_node):
                if prop.type in ("shorthand_property_identifier_pattern",
                                 "shorthand_property_identifier"):
                    self.env[text_of(prop, self.src)] = tv
                elif prop.type == "pair_pattern":
                    v = prop.child_by_field_name("value")
                    if v is not None and v.type == "identifier":
                        self.env[text_of(v, self.src)] = tv

    def _exec_if(self, node):
        cond = node.child_by_field_name("condition")
        if cond is not None:
            self._eval(cond)
        saved = dict(self.env)
        cons = node.child_by_field_name("consequence")
        if cons is not None:
            self._exec(cons)
        cons_env, self.env = self.env, dict(saved)
        alt = node.child_by_field_name("alternative")
        if alt is not None:
            self._exec(alt)
        merged = dict(self.env)
        for k, v in cons_env.items():
            merged[k] = merged.get(k, CLEAN).union(v)
        self.env = merged

    def _exec_for_in_of(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        body = node.child_by_field_name("body")
        rt = self._eval(right) if right is not None else CLEAN
        is_of = node.type == "for_of_statement"
        names = []
        if left is not None:
            names = [text_of(c, self.src) for c in _iter_nodes(left)
                     if c.type == "identifier" and c.parent.type in
                     ("lexical_declaration", "variable_declaration", "for_in_statement",
                      "for_of_statement", "array_pattern")]
        if names:
            if is_of:
                # for (const k of Object.keys(obj)) / entries
                self.env[names[0]] = T(rt.key_origins | rt.origins)
                if len(names) > 1:
                    self.env[names[1]] = rt
            else:
                self.env[names[0]] = T(rt.key_origins | rt.origins)
            if rt.tainted:
                self.has_key_loop = True
        if body is not None:
            self._exec(body)

    # -- assignments -----------------------------------------------------------
    def _assign(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        tv = self._eval(right) if right is not None else CLEAN
        if left is None:
            return tv
        danger = _chain_danger_key(left, self.src)
        if danger is not None:
            self._sink("PP005", tv.origins | frozenset({SRC_HTTP}), left,
                       f"explicit write through key '{danger}'")
            return tv
        if left.type == "identifier":
            self.env[text_of(left, self.src)] = tv
            return tv
        if left.type == "member_expression":
            if tv.from_json and tv.tainted:
                self._sink("PP003", tv.src_origins, left,
                           "JSON.parse result of tainted input assigned directly "
                           f"into '{text_of(left, self.src)}'")
            obj = left.child_by_field_name("object")
            if obj is not None and obj.type == "identifier":
                cur = self.env.get(text_of(obj, self.src), CLEAN)
                self.env[text_of(obj, self.src)] = cur.union(tv)
            return tv
        if left.type == "subscript_expression":
            obj = left.child_by_field_name("object")
            idx = left.child_by_field_name("index")
            idx_text = text_of(idx, self.src).strip("'\"") if idx is not None else ""
            if idx_text in DANGEROUS_KEYS:
                self._sink("PP005", tv.origins | frozenset({SRC_HTTP}), left,
                           f"explicit write to key '{idx_text}'")
                return tv
            it = self._eval(idx) if idx is not None else CLEAN
            idx_name = text_of(idx, self.src) if idx is not None else ""
            if it.tainted and idx_name not in self.guarded_keys:
                self.has_dynamic_write = True
                self._sink("PP004", it.origins | it.key_origins, left,
                           f"computed write '{text_of(left, self.src)}' with "
                           f"attacker-controlled key '{idx_name}'")
            if obj is not None and obj.type == "identifier":
                cur = self.env.get(text_of(obj, self.src), CLEAN)
                self.env[text_of(obj, self.src)] = cur.union(
                    T(frozenset(), it.origins | it.key_origins))
            return tv
        return tv

    def _sink(self, rule, origins, node, detail):
        self.sink_events.append((rule, frozenset(origins),
                                 node.start_point[0] + 1, node.start_point[1] + 1, detail))

    # -- expressions -------------------------------------------------------------
    def _eval(self, node) -> T:
        if node is None:
            return CLEAN
        t = node.type
        if t == "identifier":
            return self.env.get(text_of(node, self.src), CLEAN)
        if t in ("string", "number", "true", "false", "null", "undefined",
                 "regex", "template_string") and t != "template_string":
            return CLEAN
        if t == "template_string":
            out = CLEAN
            for c in node.named_children:
                if c.type == "template_substitution":
                    for e in c.named_children:
                        out = out.union(self._eval(e))
            return out
        if t == "member_expression":
            d = dotted(node, self.src)
            if d and REQ_OBJ_RE.match(d):
                # request body/query/params: attacker controls values AND keys
                return T(frozenset({SRC_HTTP}), frozenset({SRC_HTTP}))
            if d and QUERY_RE.match(d):
                return T(frozenset({SRC_QUERY}))
            return self._eval(node.child_by_field_name("object"))
        if t == "subscript_expression":
            obj = self._eval(node.child_by_field_name("object"))
            idx = node.child_by_field_name("index")
            it = self._eval(idx) if idx is not None else CLEAN
            return T(obj.origins | obj.key_origins | it.origins,
                     obj.key_origins, obj.from_json)
        if t == "call_expression":
            return self._eval_call(node)
        if t == "new_expression":
            ctor = node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            if ctor is not None and text_of(ctor, self.src) == "URLSearchParams":
                return self._eval(args.named_children[0]) if args and args.named_children else CLEAN
            return CLEAN
        if t == "assignment_expression":
            return self._assign(node)
        if t == "augmented_assignment_expression":
            return self._eval(node.child_by_field_name("right"))
        if t == "object":
            out = CLEAN
            for c in node.named_children:
                if c.type == "pair":
                    v = c.child_by_field_name("value")
                    if v is not None:
                        out = out.union(self._eval(v))
                elif c.type == "spread_element":
                    for e in c.named_children:
                        out = out.union(self._eval(e))
            return out
        if t == "array":
            out = CLEAN
            for c in node.named_children:
                out = out.union(self._eval(c))
            return out
        if t in ("binary_expression", "unary_expression", "update_expression",
                 "ternary_expression", "await_expression", "parenthesized_expression",
                 "sequence_expression", "spread_element", "template_substitution",
                 "type_assertion", "as_expression", "satisfies_expression",
                 "non_null_expression"):
            out = CLEAN
            for c in node.named_children:
                out = out.union(self._eval(c))
            return out
        if t in FUNC_TYPES:
            return CLEAN
        out = CLEAN
        for c in node.named_children:
            out = out.union(self._eval(c))
        return out

    # -- calls ---------------------------------------------------------------------
    def _eval_call(self, node) -> T:
        fn = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node is not None else []
        arg_ts = [self._eval(a) for a in args]
        any_taint = CLEAN
        for a in arg_ts:
            any_taint = any_taint.union(a)

        fn_text = text_of(fn, self.src) if fn is not None else ""
        d = dotted(fn, self.src) if fn is not None else None

        # --- well-known sources / sinks on dotted names ---------------------
        if d in ("localStorage.getItem", "sessionStorage.getItem",
                 "window.localStorage.getItem", "window.sessionStorage.getItem"):
            return T(frozenset({SRC_LS}))
        if d == "JSON.parse":
            src = arg_ts[0] if arg_ts else CLEAN
            return T(src.origins, src.origins | src.key_origins, from_json=src.tainted)
        if d == "Object.assign":
            return self._object_assign(node, args, arg_ts)
        if d in ("Object.keys", "Object.values", "Object.entries", "Object.getOwnPropertyNames"):
            src = arg_ts[0] if arg_ts else CLEAN
            return T(src.key_origins | src.origins, src.key_origins)
        if fn_text == "fetch":
            return T(frozenset({SRC_HTTP}))
        if fn_text == "require":
            return CLEAN

        # --- method call on a receiver ---------------------------------------
        if fn is not None and fn.type == "member_expression":
            obj_t = self._eval(fn.child_by_field_name("object"))
            prop = fn.child_by_field_name("property")
            prop_name = text_of(prop, self.src) if prop is not None else ""
            if prop_name in ("get", "getAll") and obj_t.tainted:
                return obj_t  # URLSearchParams.get etc.
            if prop_name in ("json", "text") and obj_t.tainted:
                return T(obj_t.origins, obj_t.origins | obj_t.key_origins,
                         from_json=obj_t.tainted)
            obj_node = fn.child_by_field_name("object")
            if obj_node is not None and obj_node.type == "identifier":
                imp = self.mod.imports.get(text_of(obj_node, self.src))
                if imp and imp[1] == "*" and imp[0]:
                    summary = self.resolve_summary(imp[0], prop_name)
                    if summary is not None:
                        return self._apply_summary(node, summary, args, arg_ts, CLEAN)
            summary = self._resolve_method(prop_name)
            if summary is not None:
                return self._apply_summary(node, summary, args, arg_ts, obj_t)
            return obj_t  # conservative: method on tainted receiver stays tainted

        # --- plain function call ----------------------------------------------
        if fn is not None and fn.type == "identifier":
            name = fn_text
            summary = self._resolve_name(name)
            if summary is not None:
                if summary.module == self.mod.id and summary.name == self.fdef.name:
                    self.recursive = True
                return self._apply_summary(node, summary, args, arg_ts, CLEAN)
            keys = self._key_control(arg_ts)
            if MERGE_NAME.match(name) and keys and not self._null_proto_target(args):
                self._sink("PP001", keys, node,
                           f"tainted object reaches external merge-like "
                           f"sink '{name}()'")
            return CLEAN
        return CLEAN

    @staticmethod
    def _key_control(arg_ts) -> frozenset:
        """Origins through which the attacker controls object *keys*."""
        out: set = set()
        for a in arg_ts:
            out |= set(a.key_origins)
            if a.from_json:
                out |= set(a.origins)
        return frozenset(out)

    def _null_proto_target(self, args) -> bool:
        if not args:
            return False
        a = args[0]
        if a.type == "call_expression":
            f = a.child_by_field_name("function")
            if f is not None and dotted(f, self.src) == "Object.create":
                return True
        return False

    def _object_assign(self, node, args, arg_ts) -> T:
        if not args:
            return CLEAN
        target_t = CLEAN
        null_proto = self._null_proto_target(args)
        for i, a in enumerate(arg_ts[1:], start=1):
            if not a.tainted or null_proto:
                continue
            if a.from_json:
                self._sink("PP003", a.src_origins or a.param_origins, node,
                           "Object.assign merges JSON.parse result of tainted input")
            elif a.key_origins:
                self._sink("PP002", a.key_origins, node,
                           "Object.assign copies attacker-controlled source object")
            target_t = target_t.union(a)
        # taint the target binding
        if args and args[0].type == "identifier":
            name = text_of(args[0], self.src)
            self.env[name] = self.env.get(name, CLEAN).union(target_t)
        return self.env.get(text_of(args[0], self.src), target_t) \
            if args and args[0].type == "identifier" else target_t

    # -- name resolution ---------------------------------------------------------
    def _resolve_name(self, name) -> Summary | None:
        if name in self.mod.summaries:
            return self.mod.summaries[name]
        if name in self.mod.methods and self.fdef.kind == "method":
            return self.mod.summaries.get(name)
        imp = self.mod.imports.get(name)
        if imp and imp[0]:
            mod_id, imported = imp
            if imported == "*":
                return None
            return self.resolve_summary(mod_id, imported)
        return None

    def _resolve_method(self, prop_name) -> Summary | None:
        if prop_name in self.mod.methods:
            return self.mod.summaries.get(prop_name)
        return None

    # -- applying a callee summary -------------------------------------------------
    def _apply_summary(self, node, summary: Summary, args, arg_ts, recv_t) -> T:
        cross_module = summary.module != self.mod.id
        self.calls.append(CallRecord(
            callee_module=summary.module, callee_name=summary.name,
            arg_origins=[sorted(a.origins | a.key_origins) for a in arg_ts],
            arg_keys=[sorted(a.key_origins) for a in arg_ts],
            line=node.start_point[0] + 1, col=node.start_point[1] + 1,
            null_proto_target=self._null_proto_target(args)))
        null_proto = self._null_proto_target(args)
        keys = self._key_control(arg_ts)
        # merge-like callee with key-controlled input and no sanitisation
        name_match = MERGE_NAME.match(summary.name) is not None
        if (summary.merge_like or name_match) and keys \
                and not summary.sanitizes_keys and not null_proto:
            self._sink_x("PP001", keys, node, cross_module,
                         f"tainted object reaches deep-merge sink "
                         f"'{summary.name}()' ({summary.module})")
        # propagate callee sinks to our params / local findings
        if not null_proto:
            for pidx, rule, line, detail in summary.sink_from:
                if pidx >= len(arg_ts):
                    continue
                a = arg_ts[pidx]
                o = a.key_origins if rule in ("PP001", "PP004") \
                    else (a.origins | a.key_origins)
                if o:
                    self._sink_x(rule, o, node, cross_module,
                                 f"{detail} [via {summary.name}() @ {summary.module}]")
        # return taint; a sanitising callee strips key control from its result
        out = CLEAN
        for pidx in summary.ret_from:
            if pidx < len(arg_ts):
                out = out.union(arg_ts[pidx])
        if summary.sanitizes_keys:
            out = T(out.origins, frozenset(), False)
        return out.union(recv_t) if recv_t.tainted and summary.name in self.mod.methods else out

    def _sink_x(self, rule, origins, node, cross_module, detail):
        """Record a sink event. Cross-module SRC findings are left to the
        engine's global call pass (which adds chain info); param origins always
        stay — they feed this function's own summary."""
        if cross_module:
            origins = frozenset(o for o in origins if o.startswith("P"))
        if origins:
            self._sink(rule, origins, node, detail)


def _chain_danger_key(node, src) -> str | None:
    """Dangerous key anywhere in a member/subscript chain (write position)."""
    n = node
    while n is not None:
        if n.type == "member_expression":
            prop = n.child_by_field_name("property")
            if prop is not None and text_of(prop, src) in DANGEROUS_KEYS:
                return text_of(prop, src)
            n = n.child_by_field_name("object")
        elif n.type == "subscript_expression":
            idx = n.child_by_field_name("index")
            if idx is not None and text_of(idx, src).strip("'\"") in DANGEROUS_KEYS:
                return text_of(idx, src).strip("'\"")
            n = n.child_by_field_name("object")
        else:
            return None
    return None


def _call_arg_idents(cond, src) -> set:
    out = set()
    for n in _iter_nodes(cond):
        if n.type == "call_expression":
            args = n.child_by_field_name("arguments")
            if args:
                for a in args.named_children:
                    if a.type == "identifier":
                        out.add(text_of(a, src))
    return out


def _compared_idents(cond, src) -> set:
    out = set()
    for n in _iter_nodes(cond):
        if n.type == "binary_expression":
            for side in (n.child_by_field_name("left"), n.child_by_field_name("right")):
                if side is not None and side.type == "identifier":
                    out.add(text_of(side, src))
    return out
