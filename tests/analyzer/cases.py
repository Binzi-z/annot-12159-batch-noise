"""50-sample acceptance corpus for the prototype-pollution analyzer.

Each case is a self-contained mini-repo. `expect` lists rules that MUST fire
(positive cases); negative cases expect zero findings.
"""

DEEP_MERGE = """\
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
"""

FLAT_MERGE = """\
export function merge(target, source) {
  for (const k in source) { target[k] = source[k]; }
  return target;
}
"""

CASES = [
    # ------------------------------------------------ positives (30) -------
    {"id": "p01-basic-merge-body", "expect": ["PP001"], "files": {
        "src/app.js": DEEP_MERGE + """
function handle(req, res) { res.send(deepMerge({}, req.body)); }
"""}},
    {"id": "p02-merge-query", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
function handle(req, res) { merge(config, req.query); }
const config = {};
"""}},
    {"id": "p03-localstorage-json-merge", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
function init() {
  const d = JSON.parse(localStorage.getItem('cfg'));
  merge(defaults, d);
}
const defaults = {};
"""}},
    {"id": "p04-recursive-object-assign", "expect": ["PP002"], "files": {
        "src/app.js": """
function handle(req, res) {
  const cfg = {};
  Object.assign(cfg, req.body);
  res.send(cfg);
}
"""}},
    {"id": "p05-json-parse-direct-assign", "expect": ["PP003"], "files": {
        "src/app.js": """
const appCfg = {};
function handle(req, res) { appCfg.plugins = JSON.parse(req.body); }
"""}},
    {"id": "p06-forin-copy-loop", "expect": ["PP004"], "files": {
        "src/app.js": """
const cfg = {};
function handle(req, res) {
  for (const k in req.body) { cfg[k] = req.body[k]; }
}
"""}},
    {"id": "p07-cross-package-merge", "expect": ["PP001"], "files": {
        "package.json": '{ "name": "mono", "workspaces": ["packages/*"] }',
        "packages/core/package.json": '{ "name": "@mono/core", "main": "index.js" }',
        "packages/core/index.js": FLAT_MERGE,
        "packages/web/package.json": '{ "name": "@mono/web" }',
        "packages/web/src/handler.js": """
import { merge } from '@mono/core';
export function h(req, res) { return merge({}, req.body); }
"""}},
    {"id": "p08-path-alias", "expect": ["PP001"], "files": {
        "tsconfig.json": '{ "compilerOptions": { "baseUrl": ".", "paths": { "@utils/*": ["src/utils/*"] } } }',
        "src/utils/merge.ts": """
export function merge(target: any, source: any) {
  for (const k in source) { target[k] = source[k]; }
  return target;
}
""",
        "src/app.ts": """
import { merge } from '@utils/merge';
export function handle(req: any, res: any) { return merge({}, req.query); }
"""}},
    {"id": "p09-proto-direct-write", "expect": ["PP005"], "files": {
        "src/app.js": """
function escalate(obj) { obj["__proto__"].isAdmin = true; }
"""}},
    {"id": "p10-external-defaultsdeep", "expect": ["PP001"], "files": {
        "src/app.js": """
import { defaultsDeep } from 'lodash';
function handle(req, res) { defaultsDeep(cfg, req.body); }
const cfg = {};
"""}},
    {"id": "p11-urlsearchparams", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
function init() {
  const raw = new URLSearchParams(location.search);
  const d = JSON.parse(raw.get('cfg'));
  merge(opts, d);
}
const opts = {};
"""}},
    {"id": "p12-monorepo-override", "expect": ["PP001"], "files": {
        "package.json": '{ "name": "mono", "workspaces": ["packages/*"] }',
        "packages/a/package.json": '{ "name": "@mono/a", "main": "index.js" }',
        "packages/a/index.js": """
export function getConfig() {
  const cfg = {};
  for (const k in defaults) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    cfg[k] = defaults[k];
  }
  return cfg;
}
const defaults = { theme: 'light' };
""",
        "packages/b/package.json": '{ "name": "@mono/b" }',
        "packages/b/index.js": FLAT_MERGE + """
import { getConfig } from '@mono/a';
export function h(req, res) { return merge(getConfig(), req.body); }
"""}},
    {"id": "p13-class-method-merge", "expect": ["PP001"], "files": {
        "src/app.js": """
class Merger {
  merge(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
}
function h(req, res) { return new Merger().merge({}, req.body); }
"""}},
    {"id": "p14-arrow-export-merge", "expect": ["PP001"], "files": {
        "src/util.js": """
export const merge = (t, s) => { for (const k in s) { t[k] = s[k]; } return t; };
""",
        "src/app.js": """
import { merge } from './util.js';
function h(req, res) { return merge({}, req.body); }
"""}},
    {"id": "p15-ts-variant", "expect": ["PP001"], "files": {
        "src/app.ts": """
interface Cfg { [k: string]: unknown }
function merge(t: Cfg, s: Cfg): Cfg {
  for (const k in s) { t[k] = s[k]; }
  return t;
}
export function h(req: any, res: any) { return merge({}, req.body); }
"""}},
    {"id": "p16-tsx-localstorage", "expect": ["PP001"], "files": {
        "src/app.tsx": """
const merge = (t: any, s: any) => { for (const k in s) { t[k] = s[k]; } return t; };
export const init = () => merge({}, JSON.parse(localStorage.getItem('x') || '{}'));
"""}},
    {"id": "p17-express-handler", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
const express = require('express');
const app = express();
const config = {};
app.post('/c', (req, res) => { merge(config, req.query); res.send('ok'); });
"""}},
    {"id": "p18-json-parse-localstorage-assign", "expect": ["PP003"], "files": {
        "src/app.js": """
const config = {};
function init() {
  const d = JSON.parse(localStorage.getItem('x'));
  config.servers = d;
}
"""}},
    {"id": "p19-entries-loop", "expect": ["PP004"], "files": {
        "src/app.js": """
const target = {};
function h(req, res) {
  for (const [k, v] of Object.entries(req.body)) { target[k] = v; }
}
"""}},
    {"id": "p20-intermediate-vars", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
const cfg = {};
function h(req, res) { const b = req.body; const c = b; merge(cfg, c); }
"""}},
    {"id": "p21-func-decl-cross-file", "expect": ["PP001"], "files": {
        "src/merge.js": """
export function mergeDeep(t, s) {
  for (const k in s) {
    if (s[k] && typeof s[k] === 'object') { t[k] = mergeDeep(t[k] || {}, s[k]); }
    else { t[k] = s[k]; }
  }
  return t;
}
""",
        "src/app.js": """
import { mergeDeep } from './merge.js';
function h(req, res) { return mergeDeep({}, req.body); }
"""}},
    {"id": "p22-req-params-extend", "expect": ["PP001"], "files": {
        "src/app.js": """
function extend(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
const cfg = {};
function h(req, res) { extend(cfg, req.params); }
"""}},
    {"id": "p23-global-config-merge", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
function h(req, res) {
  globalThis.__config = merge(globalThis.__config || {}, req.body);
}
"""}},
    {"id": "p24-parsed-body-key-write", "expect": ["PP004"], "files": {
        "src/app.js": """
const o = {};
function h(req, res) {
  for (const k in JSON.parse(req.body)) { o[k] = 1; }
}
"""}},
    {"id": "p25-fetch-json-merge", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
const cfg = {};
async function h(req) {
  const r = await fetch('/api/cfg');
  const d = await r.json();
  merge(cfg, d);
}
"""}},
    {"id": "p26-session-storage-assign", "expect": ["PP003"], "files": {
        "src/app.js": """
const config = {};
function init() { config.auth = JSON.parse(sessionStorage.getItem('s')); }
"""}},
    {"id": "p27-defaults-name-local", "expect": ["PP001"], "files": {
        "src/app.js": """
function defaults(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
const cfg = {};
function h(req, res) { defaults(cfg, req.body); }
"""}},
    {"id": "p28-reexport-chain", "expect": ["PP001"], "files": {
        "package.json": '{ "name": "mono", "workspaces": ["packages/*"] }',
        "packages/core/package.json": '{ "name": "@mono/core", "main": "index.js" }',
        "packages/core/index.js": FLAT_MERGE,
        "packages/mid/package.json": '{ "name": "@mono/mid", "main": "index.js" }',
        "packages/mid/index.js": "export { merge } from '@mono/core';\n",
        "packages/web/package.json": '{ "name": "@mono/web" }',
        "packages/web/app.js": """
import { merge } from '@mono/mid';
function h(req, res) { return merge({}, req.body); }
"""}},
    {"id": "p29-nested-member-source", "expect": ["PP001"], "files": {
        "src/app.js": FLAT_MERGE.replace("export ", "") + """
const cfg = {};
function h(req, res) { merge(cfg, req.body.payload); }
"""}},
    {"id": "p30-object-assign-json", "expect": ["PP003"], "files": {
        "src/app.js": """
function h(req, res) {
  const o = {};
  Object.assign(o, JSON.parse(req.body));
}
"""}},
    # ------------------------------------------------ negatives (20) -------
    {"id": "n01-guard-hasown", "expect": [], "files": {
        "src/app.js": """
function merge(t, s) {
  for (const k in s) {
    if (!Object.prototype.hasOwnProperty.call(s, k)) continue;
    t[k] = s[k];
  }
  return t;
}
const cfg = {};
function h(req, res) { merge(cfg, req.body); }
"""}},
    {"id": "n02-guard-blacklist", "expect": [], "files": {
        "src/app.js": """
function merge(t, s) {
  for (const k in s) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    t[k] = s[k];
  }
  return t;
}
const cfg = {};
function h(req, res) { merge(cfg, req.body); }
"""}},
    {"id": "n03-guard-whitelist", "expect": [], "files": {
        "src/app.js": """
const ALLOWED = ['theme', 'lang'];
function merge(t, s) {
  for (const k in s) {
    if (!ALLOWED.includes(k)) continue;
    t[k] = s[k];
  }
  return t;
}
const cfg = {};
function h(req, res) { merge(cfg, req.body); }
"""}},
    {"id": "n04-null-proto-target", "expect": [], "files": {
        "src/app.js": """
function merge(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
function h(req, res) { merge(Object.create(null), req.body); }
"""}},
    {"id": "n05-static-literals", "expect": [], "files": {
        "src/app.js": """
function merge(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
const cfg = merge({}, { a: 1, b: { c: 2 } });
"""}},
    {"id": "n06-json-parse-literal", "expect": [], "files": {
        "src/app.js": """
const d = JSON.parse('{"a": 1}');
console.log(d.a);
"""}},
    {"id": "n07-python-not-js", "expect": [], "files": {
        "tools/merge_config.py": '''
def merge_config(target, source):
    # looks like the JS gadget: target["__proto__"] must NOT be read as JS
    for key in source:
        target[key] = source[key]
    return target

merge_config({}, {"theme": "dark"})
''',
        "src/app.js": "console.log('ok');\n"}},
    {"id": "n08-fs-readfile", "expect": [], "files": {
        "src/app.js": """
const fs = require('fs');
function merge(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
const cfg = JSON.parse(fs.readFileSync('./c.json', 'utf8'));
merge({}, cfg);
"""}},
    {"id": "n09-custom-validator-pick", "expect": [], "files": {
        "src/app.js": """
function pick(source, allowed) {
  const out = {};
  for (const k of allowed) {
    if (Object.prototype.hasOwnProperty.call(source, k)) out[k] = source[k];
  }
  return out;
}
function merge(t, s) { for (const k in s) { t[k] = s[k]; } return t; }
const cfg = {};
function h(req, res) { merge(cfg, pick(req.body, ['theme'])); }
"""}},
    {"id": "n10-object-assign-literal", "expect": [], "files": {
        "src/app.js": """
const cfg = {};
Object.assign(cfg, { port: 8080, host: 'localhost' });
"""}},
    {"id": "n11-localstorage-read-only", "expect": [], "files": {
        "src/app.js": """
function init() {
  const v = JSON.parse(localStorage.getItem('x'));
  console.log(v.name, v.theme);
}
"""}},
    {"id": "n12-explicit-key-copy", "expect": [], "files": {
        "src/app.js": """
const cfg = {};
function h(req, res) {
  const b = req.body;
  cfg.name = b.name;
  cfg.port = b.port;
}
"""}},
    {"id": "n13-python-merge-word", "expect": [], "files": {
        "lib/utils.py": '''
def merge(a, b):
    a.update(b)
    return a

merge({"x": 1}, {"y": 2})
'''}},
    {"id": "n14-ts-types-only", "expect": [], "files": {
        "src/types.ts": """
export interface Config { theme: string; port: number }
export type MergeFn = (t: Config, s: Partial<Config>) => Config;
"""}},
    {"id": "n15-map-based", "expect": [], "files": {
        "src/app.js": """
function h(req, res) {
  const m = new Map();
  for (const k in req.body) { m.set(k, req.body[k]); }
  res.send([...m.keys()]);
}
"""}},
    {"id": "n16-object-keys-guarded", "expect": [], "files": {
        "src/app.js": """
const cfg = {};
function h(req, res) {
  Object.keys(req.body).forEach(k => {
    if (['a', 'b'].includes(k)) { cfg[k] = req.body[k]; }
  });
}
"""}},
    {"id": "n17-array-concat", "expect": [], "files": {
        "src/app.js": """
function h(req, res) { const list = [].concat(req.body); res.send(list); }
"""}},
    {"id": "n18-query-string-concat", "expect": [], "files": {
        "src/app.js": """
function nav() { const url = '/api' + location.search; fetch(url); }
"""}},
    {"id": "n19-cross-pkg-sanitized", "expect": [], "files": {
        "package.json": '{ "name": "mono", "workspaces": ["packages/*"] }',
        "packages/core/package.json": '{ "name": "@mono/core", "main": "index.js" }',
        "packages/core/index.js": """
export function merge(t, s) {
  for (const k in s) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    t[k] = s[k];
  }
  return t;
}
""",
        "packages/web/package.json": '{ "name": "@mono/web" }',
        "packages/web/app.js": """
import { merge } from '@mono/core';
function h(req, res) { return merge({}, req.body); }
"""}},
    {"id": "n20-commented-code", "expect": [], "files": {
        "src/app.js": """
// merge(cfg, req.body);
/* for (const k in req.body) { target[k] = req.body[k]; } */
const cfg = {};
function h(req, res) { res.send('ok'); }
"""}},
]

assert len(CASES) == 50, len(CASES)
