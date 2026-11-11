"""cns_interop: the universal AI interface layer (UAI-1) beside CNS, never inside it.

`cns` holds shapes, `cns_composition` holds behaviour over them inside one process, and this package is how a
system outside that process, written in any language, exchanges requests, evidence and decisions with one that uses
CNS without becoming part of it. See docs/interop/UAI-1.md.
"""
