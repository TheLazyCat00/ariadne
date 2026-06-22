"""Synthetic-IL validation for the tainted-gate analysis in dotnet_il.py.

No dotnet SDK is required: we assemble REAL CIL bytes, decode them with the
backend's own decoder, run the analysis, and (for the writer) force the bytes and
re-decode to prove the patch is well-formed. Two methods are exercised:

  * Main  -- mirrors fixtures/dotnet_flag: isLocked gated through the overloaded
             Flip helper. Validates detection, helper-aware constant resolution,
             the def-site value region, and the length-preserving byte writer.
  * Main2 -- an inlined gate (getenv()==key branched on directly, no local) to
             validate the inlined-gate path.

Run: python tests/test_gate_taint.py
"""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from calltree_backends.dotnet_il import DotNetILFrontend, _decode_cil

# --- a tiny CIL assembler (real opcode bytes, real sizes) --------------------
OPC = {"nop":0x00,"ldarg.0":0x02,"ldloc.0":0x06,"ldloc.1":0x07,"ldloc.2":0x08,
       "stloc.0":0x0A,"stloc.1":0x0B,"stloc.2":0x0C,
       "ldc.i4.0":0x16,"ldc.i4.1":0x17,"ldc.i4.3":0x19,
       "ret":0x2A,"br.s":0x2B,"brfalse.s":0x2C,"brtrue.s":0x2D,
       "call":0x28,"ldstr":0x72}
def _size(op): return 5 if op in ("call","ldstr") else (2 if op.endswith(".s") and op!="ldc.i4.s" else 1)

def assemble(prog):
    """prog items: (op, attrs) or ("@label",). attrs may carry text/tok/label.
    Returns (code_bytes, strmap, callmap) where the maps give ldstr/call text."""
    off=0; labels={}; lay=[]
    for it in prog:
        if it[0].startswith("@"): labels[it[0][1:]]=off; continue
        op=it[0]; a=it[1] if len(it)>1 else {}
        lay.append((off,op,a)); off+=_size(op)
    code=bytearray(); strmap={}; callmap={}; tok=0x70000001; ctok=0x06000001
    import struct
    for o,op,a in lay:
        code.append(OPC[op])
        if op=="ldstr":
            t=a.get("tok",tok); tok=max(tok,t)+1
            strmap[t]=a.get("text",""); code+=struct.pack("<I",t)
        elif op=="call":
            t=a.get("tok",ctok); ctok=max(ctok,t)+1
            callmap[t]=a.get("text",""); code+=struct.pack("<I",t)
        elif op.endswith(".s") and op!="ldc.i4.s":
            disp=labels[a["label"]]-(o+2); code+=struct.pack("b",disp)
    return bytes(code), strmap, callmap

def decode(prog):
    code,strmap,callmap=assemble(prog)
    ins=_decode_cil(code, None)               # pe=None -> text unresolved
    for x in ins:                              # post-resolve text from our maps
        if x["op"]=="ldstr": x["text"]=strmap.get(x["operand"])
        elif x["op"] in ("call","callvirt","newobj"): x["text"]=callmap.get(x["operand"])
    return code, ins

ENV="System.Environment::GetEnvironmentVariable"
NEQ="System.String::op_Inequality"
EQ ="System.String::op_Equality"
WL ="System.Console::WriteLine"
FLIP_BOOL=0x06000111
FLIP_INT =0x06000222

# Mirror of dotnet_flag Main; every gate is Flip(isLocked); Flip(int) is non-gate.
MAIN = [
    ("ldstr",{"text":"ARIADNE_LICENSE"}), ("call",{"text":ENV}), ("stloc.0",),   # license
    ("ldloc.0",), ("ldstr",{"text":"ARIADNE-7F3A-2025"}), ("call",{"text":NEQ}), ("stloc.1",),  # isLocked
    ("ldloc.1",), ("call",{"text":"Program::Flip","tok":FLIP_BOOL}), ("brfalse.s",{"label":"else1"}),
    ("ldstr",{"text":"License accepted. Welcome!"}), ("call",{"text":WL}), ("br.s",{"label":"after1"}),
    ("@else1",), ("ldstr",{"text":"License invalid. Access denied."}), ("call",{"text":WL}),
    ("@after1",),
    ("ldloc.1",), ("call",{"text":"Program::Flip","tok":FLIP_BOOL}), ("brfalse.s",{"label":"after2"}),
    ("ldstr",{"text":"Premium features unlocked."}), ("call",{"text":WL}),
    ("@after2",),
    ("ldc.i4.3",), ("stloc.2",),                                   # balance (int)
    ("ldstr",{"text":"flip(3) = "}), ("ldloc.2",), ("call",{"text":"Program::Flip","tok":FLIP_INT}), ("call",{"text":WL}),
    ("ldloc.1",), ("call",{"text":"Program::Flip","tok":FLIP_BOOL}), ("brtrue.s",{"label":"ret1"}),
    ("ldc.i4.0",), ("ret",),
    ("@ret1",), ("ldc.i4.1",), ("ret",),
]

# Inlined gate: if (getenv()==key) win; else lose;  -- no stored local.
MAIN2 = [
    ("ldstr",{"text":"ENVKEY"}), ("call",{"text":ENV}), ("ldstr",{"text":"secret"}), ("call",{"text":EQ}),
    ("brfalse.s",{"label":"el"}),
    ("ldstr",{"text":"access granted welcome"}), ("call",{"text":WL}), ("br.s",{"label":"en"}),
    ("@el",), ("ldstr",{"text":"denied invalid"}), ("call",{"text":WL}),
    ("@en",), ("ret",),
]

def make_method(name, prog):
    code, ins = decode(prog)
    return code, {"name":name, "ins":ins, "body":{"code_off":0,"code_size":len(code),"more_sects":False},
                  "calls":[x["text"] for x in ins if x["op"]=="call" and x.get("text")],
                  "strings":[x["text"] for x in ins if x["op"]=="ldstr" and x.get("text")]}

def main():
    fe=DotNetILFrontend.__new__(DotNetILFrontend)
    # Flip(bool) == !b  ->  ldarg.0; ldc.i4.0; ceq; ret   (ceq is 0xFE 0x01)
    fe._token_methods={FLIP_BOOL: _decode_cil(bytes([0x02,0x16,0xFE,0x01,0x2A]), None)}

    code, m = make_method("Program::Main", MAIN)
    cands=fe._gate_taint_candidates(m)
    assert len(cands)==1, "expected one typed-local gate, got %r" % cands
    c=cands[0]
    assert c["local"]==1, c["local"]
    assert "GetEnvironmentVariable" in c["source"], c["source"]
    assert c["indirect_via"]==["Program::Flip"], c["indirect_via"]
    assert len(c["branch_offs"])==3, c["branch_offs"]
    assert c["licensed"]=="fall-through", c["licensed"]
    assert any("accepted" in w.lower() for w in c["wins"]), c["wins"]
    # helper-aware constant resolution: forcing isLocked=0 (unlocked) opens gates.
    assert c["force_const"]==0, "expected force constant 0 (unlocked), got %r" % c["force_const"]
    assert c["region"] is not None, "value region must be byte-determinable"
    assert c["significance"] is not None

    # --- writer: force the def region, then re-decode and check well-formedness ---
    with tempfile.TemporaryDirectory() as d:
        prim=os.path.join(d,"flag.dll"); open(prim,"wb").write(code)
        fe.primary=prim
        out=os.path.join(d,"flag.patched.dll")
        wrote,_=fe._emit_gate_forces([m], out_arg=out)
        assert wrote, "writer should have applied a force"
        patched=open(out,"rb").read()
        assert len(patched)==len(code), "patch must be length-preserving"
        pins=_decode_cil(patched, None)
        s_off,e_off=c["region"]
        region=[x for x in pins if s_off<=x["off"]<e_off]
        assert region[-1]["op"]=="ldc.i4.0", "region must end in ldc.i4.0, got %r" % region[-1]["op"]
        assert all(x["op"]=="nop" for x in region[:-1]), "region prefix must be nop padding"
        nxt=[x for x in pins if x["off"]==e_off][0]
        assert nxt["op"]=="stloc.1", "forced constant must feed the original stloc, got %r" % nxt["op"]

    # --- inlined gate path ---
    _, m2 = make_method("Program::Main2", MAIN2)
    assert fe._gate_taint_candidates(m2)==[], "inlined method has no typed-local gate"
    inl=fe._inlined_gate_candidates(m2)
    assert len(inl)==1, "expected one inlined gate, got %r" % inl
    assert "GetEnvironmentVariable" in inl[0]["source"], inl[0]["source"]
    assert inl[0]["licensed"]=="fall-through", inl[0]["licensed"]

    print("OK: typed-local gate isolated (isLocked=local 1), force constant 0 via Flip,")
    print("    def region IL_%04x..IL_%04x writes nop*+ldc.i4.0 (length-preserving)," % c["region"])
    print("    Flip never patched, license/balance excluded, inlined gate detected.")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
