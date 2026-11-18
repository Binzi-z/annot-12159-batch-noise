"""Cross-language prototype-pollution analyzer for JS/TS + Python monorepos.

Built on tree-sitter (syntax only) plus a self-built symbol table and taint
engine. No ready-made rule sets are used; every rule is implemented here.
"""

__version__ = "0.1.0"
