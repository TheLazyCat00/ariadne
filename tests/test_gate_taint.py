"""Synthetic-IL validation for the tainted-bool gate analysis in dotnet_il.py.

dnfile/dotnet are not required: the analysis operates on the decoded instruction
list, so we hand-assemble a method that mirrors fixtures/dotnet_flag/Program.cs
Main (isLocked gated through the overloaded Flip helper) and assert the analysis
picks isLocked, never proposes patching Flip, and excludes the string/int locals.

Run: python tests/test_gate_taint.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from calltree_backends.dotnet_il import DotNetILFrontend

# Instruction byte sizes for the opcodes used below (opcode + operand).
_SIZE = {"ldstr": 5, "call": 5}
def _size(op):
    if op in _SIZE: return _SIZE[op]
    if op.endswith(".s"): return 2          # short branch: opcode + int8
    return 1                                 # ldloc.N/stloc.N/ldc.i4.N/ret/nop

def assemble(prog):
    """prog: list of (op, attrs) tuples; ("@label",) marks a label position.
    Returns a decoded-style instruction list with off/target resolved."""
    # First pass: assign offsets, record label offsets.
    offs=[]; labels={}; off=0
    for item in prog:
        if item[0].startswith("@"):
            labels[item[0][1:]]=off; continue
        op=item[0]; offs.append((off, op, item[1] if len(item)>1 else {}))
        off+=_size(op)
    # Second pass: build instruction dicts and resolve branch targets.
    ins=[]
    for o, op, attrs in offs:
        x={"off":o, "end":o+_size(op), "size":_size(op), "op":op,
           "operand":attrs.get("operand"), "target":None, "text":attrs.get("text")}
        if "label" in attrs: x["target"]=labels[attrs["label"]]
        ins.append(x)
    return ins

# Mirror of dotnet_flag Main: license<-source, isLocked<-(license != key),
# three gates all written as Flip(isLocked), plus a non-gate Flip(int) on balance.
PROG = [
    ("ldstr", {"text":"ARIADNE_LICENSE"}),
    ("call",  {"text":"System.Environment::GetEnvironmentVariable"}),
    ("stloc.0", {}),                                 # local 0 = license (string, tainted)
    ("ldloc.0", {}),
    ("ldstr", {"text":"ARIADNE-7F3A-2025"}),
    ("call",  {"text":"System.String::op_Inequality"}),
    ("stloc.1", {}),                                 # local 1 = isLocked (bool, tainted)
    # gate 1: if (Flip(isLocked)) ... else ...
    ("ldloc.1", {}),
    ("call",  {"text":"Program::Flip"}),
    ("brfalse.s", {"label":"else1"}),
    ("ldstr", {"text":"License accepted. Welcome!"}),
    ("call",  {"text":"System.Console::WriteLine"}),
    ("br.s",  {"label":"after1"}),
    ("@else1",),
    ("ldstr", {"text":"License invalid. Access denied."}),
    ("call",  {"text":"System.Console::WriteLine"}),
    ("@after1",),
    # gate 2: if (Flip(isLocked)) ...
    ("ldloc.1", {}),
    ("call",  {"text":"Program::Flip"}),
    ("brfalse.s", {"label":"after2"}),
    ("ldstr", {"text":"Premium features unlocked."}),
    ("call",  {"text":"System.Console::WriteLine"}),
    ("@after2",),
    # non-gate: int overload Flip(balance), pure arithmetic, must NOT be a gate
    ("ldc.i4.3", {}),
    ("stloc.2", {}),                                 # local 2 = balance (int)
    ("ldstr", {"text":"flip(3) = "}),
    ("ldloc.2", {}),
    ("call",  {"text":"Program::Flip"}),
    ("call",  {"text":"System.Console::WriteLine"}),
    # gate 3: return Flip(isLocked) ? 0 : 1;
    ("ldloc.1", {}),
    ("call",  {"text":"Program::Flip"}),
    ("brtrue.s", {"label":"ret1"}),
    ("ldc.i4.0", {}),
    ("ret", {}),
    ("@ret1",),
    ("ldc.i4.1", {}),
    ("ret", {}),
]

def main():
    fe=DotNetILFrontend.__new__(DotNetILFrontend)      # bypass dnfile-loading __init__
    ins=assemble(PROG)
    m={"name":"Program::Main", "ins":ins,
       "calls":[x["text"] for x in ins if x["op"]=="call"],
       "strings":[x["text"] for x in ins if x["op"]=="ldstr"]}
    cands=fe._gate_taint_candidates(m)

    assert len(cands)==1, "expected exactly one gate local, got %r" % cands
    c=cands[0]
    assert c["local"]==1, "expected isLocked == local 1, got %r" % c["local"]
    assert "GetEnvironmentVariable" in c["source"], "taint source wrong: %r" % c["source"]
    assert c["indirect_via"]==["Program::Flip"], "expected gate to flow through Flip only: %r" % c["indirect_via"]
    assert len(c["branch_offs"])==3, "expected 3 gates on isLocked, got %r" % c["branch_offs"]
    assert c["licensed"]=="fall-through", "expected licensed side fall-through, got %r" % c["licensed"]
    assert any("accepted" in w.lower() for w in c["wins"]), "win-string anchor missing: %r" % c["wins"]

    # Negative checks: the string local (0) and int local (2) are NOT gate locals.
    assert all(x["local"]!=0 for x in cands), "license (local 0) must not be a gate bool"
    assert all(x["local"]!=2 for x in cands), "balance (local 2) must not be a gate bool"

    print("OK: isLocked (local 1) isolated as the source-tainted, bool, gate-only variable")
    print("    def-site IL_%04x, gates %s, flows through %s (never patched)"
          % (c["def_off"], ", ".join("IL_%04x"%o for o in c["branch_offs"]),
             ", ".join(c["indirect_via"])))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
