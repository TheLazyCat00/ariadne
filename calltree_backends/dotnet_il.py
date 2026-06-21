#!/usr/bin/env python3
"""Standalone .NET IL frontend for Ariadne.

This backend is intentionally managed-code-aware. It analyzes CLI metadata and
CIL directly instead of asking angr/Triton to execute CoreCLR bootstrap code.
Write-capable patching is not implemented here; patch mode emits dry-run plans.
"""
import os
import sys

WIN_WORDS=["correct","granted","welcome","success","unlocked","accepted",
           "licensed","thank you","notes","access granted"]
LOSE_WORDS=["wrong","denied","invalid","incorrect","not correct","not valid",
            "fail","failed","nope","unregistered","unlicensed","locked",
            "not registered","try again","bad "]

def hr(t): print("\n"+"="*66+"\n  "+t+"\n"+"="*66)

def _read_file_prefix(path, n=16*1024*1024):
    try:
        with open(path,"rb") as f: return f.read(n)
    except Exception:
        return b""

def _glob_limited(pattern, limit=24):
    import glob
    out=[]
    try:
        for x in glob.glob(pattern):
            out.append(x)
            if len(out)>=limit: break
    except Exception: pass
    return out

# ---------------------------------------------------------------------------
# 3c. FRONTEND ROUTING: native angr vs runtime-specific IL analyzers.
# ---------------------------------------------------------------------------
def _raw_strings(data, minlen=4, maxlen=220):
    out=set(); cur=bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if minlen <= len(cur) <= maxlen:
                out.add(cur.decode("latin1","replace"))
            cur=bytearray()
    if minlen <= len(cur) <= maxlen:
        out.add(cur.decode("latin1","replace"))
    # UTF-16LE-ish printable runs, common in .NET user strings/resources.
    cur=[]
    for i in range(0, max(0,len(data)-1), 2):
        lo,hi=data[i],data[i+1]
        if hi==0 and 32 <= lo < 127:
            cur.append(chr(lo))
        else:
            if minlen <= len(cur) <= maxlen: out.add("".join(cur))
            cur=[]
    if minlen <= len(cur) <= maxlen: out.add("".join(cur))
    return sorted(out)

def _is_dotnet_cli_file(path):
    data=_read_file_prefix(path, 32*1024*1024)
    low=data.lower()
    return (b"bsjb" in data) or (b"mscoree.dll" in low) or (b"_cor" in low and b"metadata" in low)

DOTNET_RUNTIME_ASM_PREFIXES=(
    "system.", "microsoft.", "windows.", "communitytoolkit.", "winrt.",
)
DOTNET_RUNTIME_ASM_NAMES={
    "coreclr.dll", "clrjit.dll", "clrgc.dll", "clretwrc.dll", "hostfxr.dll",
    "hostpolicy.dll", "mscordaccore.dll", "mscordbi.dll",
    "system.private.corelib.dll", "system.runtime.dll", "netstandard.dll",
}

def _dotnet_is_framework_or_runtime_assembly(path, app_primary=None):
    """True for framework/runtime/support assemblies that should not be the
    default IL analysis target.  We still allow an explicit --il-assembly to
    analyze any file the user selects."""
    b=os.path.basename(path).lower()
    if app_primary and os.path.abspath(path).lower()==os.path.abspath(app_primary).lower():
        return False
    if b in DOTNET_RUNTIME_ASM_NAMES: return True
    return any(b.startswith(p) for p in DOTNET_RUNTIME_ASM_PREFIXES)

def _dotnet_payload_candidates(binary, rt, explicit=None):
    d=os.path.dirname(os.path.abspath(binary)) or "."
    base_no_ext=os.path.splitext(os.path.basename(binary))[0]
    app_primary=os.path.join(d, base_no_ext+".dll")
    c=[]
    if explicit: c.append(explicit)
    if _is_dotnet_cli_file(binary): c.append(binary)
    c += [os.path.join(d, base_no_ext+ext) for ext in (".dll",".exe")]
    c += [p for p in (rt or {}).get("payloads",[]) if p.lower().endswith((".dll",".exe"))]
    c += _glob_limited(os.path.join(d,"*.dll"), 128)
    out=[]; seen=set()
    for pth in c:
        if not pth or pth in seen: continue
        seen.add(pth)
        try:
            if not os.path.exists(pth) or not _is_dotnet_cli_file(pth): continue
            # If explicitly selected, keep it even if it is a framework assembly.
            if explicit and os.path.abspath(pth).lower()==os.path.abspath(explicit).lower():
                out.append(pth); continue
            if _dotnet_is_framework_or_runtime_assembly(pth, app_primary=app_primary):
                continue
            out.append(pth)
        except Exception: pass
    # Prefer the conventional apphost payload basename.dll, then application-ish names.
    out.sort(key=lambda x: (0 if os.path.abspath(x).lower()==os.path.abspath(app_primary).lower() else 1,
                            len(os.path.basename(x)), x.lower()))
    return out

def _safe_name(x):
    if x is None: return ""
    for a in ("value","name"):
        try:
            v=getattr(x,a)
            if v is not None: return str(v)
        except Exception: pass
    return str(x)

def _dn_row_name(row):
    if row is None: return ""
    parts=[]
    for attr in ("TypeNamespace","TypeName","Name"):
        try:
            v=getattr(row, attr)
            if v is not None: parts.append(_safe_name(v))
        except Exception: pass
    return ".".join([p for p in parts if p]) or row.__class__.__name__

def _coded_row(x):
    try:
        return x.row
    except Exception:
        return None

def _dotnet_token_table(pe, table_id):
    try:
        md=pe.net.mdtables
        names={0x02:"TypeDef",0x06:"MethodDef",0x0a:"MemberRef",0x1b:"TypeSpec",0x2b:"MethodSpec"}
        return getattr(md, names.get(table_id,""), None)
    except Exception:
        return None

def _dotnet_resolve_method_token(pe, token):
    """Best-effort method/member token name for call/callvirt opcodes."""
    table_id=(token>>24)&0xff; rid=token & 0x00ffffff
    tbl=_dotnet_token_table(pe, table_id)
    row=None
    try:
        if tbl is not None and rid>0: row=tbl.rows[rid-1]
    except Exception: row=None
    if row is None: return "token_%08x" % token
    name=_safe_name(getattr(row,"Name",None))
    cls=""
    try:
        clsrow=_coded_row(row.Class)
        cls=_dn_row_name(clsrow)
    except Exception: pass
    if not cls and table_id==0x06:
        # MethodDef rows do not carry their parent directly in dnfile's row.
        cls="MethodDef"
    return (cls+"::" if cls else "") + (name or ("token_%08x"%token))

def _dotnet_user_string(pe, token):
    try:
        if ((token>>24)&0xff) != 0x70: return None
        us=pe.net.user_strings.get(token & 0x00ffffff)
        return str(us) if us is not None else None
    except Exception:
        return None

# Minimal CIL decoder sufficient for source/sink/candidate discovery.  It is
# deliberately conservative; future IL-family frontends can implement a richer
# CFG/symbolic executor behind the same DotNetILFrontend interface.
_IL_ONE={
  0x00:("nop","none"), 0x02:("ldarg.0","none"),0x03:("ldarg.1","none"),0x04:("ldarg.2","none"),0x05:("ldarg.3","none"),
  0x06:("ldloc.0","none"),0x07:("ldloc.1","none"),0x08:("ldloc.2","none"),0x09:("ldloc.3","none"),
  0x0a:("stloc.0","none"),0x0b:("stloc.1","none"),0x0c:("stloc.2","none"),0x0d:("stloc.3","none"),
  0x0e:("ldarg.s","u1"),0x0f:("ldarga.s","u1"),0x10:("starg.s","u1"),0x11:("ldloc.s","u1"),0x12:("ldloca.s","u1"),0x13:("stloc.s","u1"),
  0x14:("ldnull","none"),0x15:("ldc.i4.m1","none"),0x16:("ldc.i4.0","none"),0x17:("ldc.i4.1","none"),0x18:("ldc.i4.2","none"),
  0x19:("ldc.i4.3","none"),0x1a:("ldc.i4.4","none"),0x1b:("ldc.i4.5","none"),0x1c:("ldc.i4.6","none"),0x1d:("ldc.i4.7","none"),
  0x1e:("ldc.i4.8","none"),0x1f:("ldc.i4.s","i1"),0x20:("ldc.i4","i4"),0x25:("dup","none"),0x26:("pop","none"),
  0x28:("call","token"),0x2a:("ret","none"),0x2b:("br.s","br1"),0x2c:("brfalse.s","br1"),0x2d:("brtrue.s","br1"),
  0x2e:("beq.s","br1"),0x2f:("bge.s","br1"),0x30:("bgt.s","br1"),0x31:("ble.s","br1"),0x32:("blt.s","br1"),0x33:("bne.un.s","br1"),
  0x38:("br","br4"),0x39:("brfalse","br4"),0x3a:("brtrue","br4"),0x3b:("beq","br4"),0x3c:("bge","br4"),0x3d:("bgt","br4"),
  0x3e:("ble","br4"),0x3f:("blt","br4"),0x40:("bne.un","br4"),0x45:("switch","switch"),0x58:("add","none"),0x59:("sub","none"),
  0x5a:("mul","none"),0x5b:("div","none"),0x5f:("and","none"),0x60:("or","none"),0x61:("xor","none"),0x65:("neg","none"),
  0x6f:("callvirt","token"),0x70:("cpobj","token"),0x71:("ldobj","token"),0x72:("ldstr","token"),0x73:("newobj","token"),
  0x74:("castclass","token"),0x75:("isinst","token"),0x7b:("ldfld","token"),0x7c:("ldflda","token"),0x7d:("stfld","token"),
  0x7e:("ldsfld","token"),0x7f:("ldsflda","token"),0x80:("stsfld","token"),0x8c:("box","token"),0x8d:("newarr","token"),
  0x8e:("ldlen","none"),0x8f:("ldelema","token"),0x90:("ldelem.i1","none"),0x91:("ldelem.u1","none"),0x92:("ldelem.i2","none"),
  0x93:("ldelem.u2","none"),0x94:("ldelem.i4","none"),0x95:("ldelem.u4","none"),0x96:("ldelem.i8","none"),0x97:("ldelem.i","none"),
  0x98:("ldelem.r4","none"),0x99:("ldelem.r8","none"),0x9a:("ldelem.ref","none"),0x9b:("stelem.i","none"),0x9c:("stelem.i1","none"),
  0x9d:("stelem.i2","none"),0x9e:("stelem.i4","none"),0x9f:("stelem.i8","none"),0xa0:("stelem.r4","none"),0xa1:("stelem.r8","none"),
  0xa2:("stelem.ref","none"),0xa3:("ldelem","token"),0xa4:("stelem","token"),0xa5:("unbox.any","token"),0xd0:("ldtoken","token"),
}
_IL_TWO={0x01:("ceq","none"),0x02:("cgt","none"),0x03:("cgt.un","none"),0x04:("clt","none"),0x05:("clt.un","none")}

def _cil_operand(code, i, kind):
    import struct
    if kind=="none": return None,i
    if kind=="u1": return code[i], i+1
    if kind=="i1": return struct.unpack_from("b",code,i)[0], i+1
    if kind=="i4": return struct.unpack_from("<i",code,i)[0], i+4
    if kind=="token": return struct.unpack_from("<I",code,i)[0], i+4
    if kind=="br1": return struct.unpack_from("b",code,i)[0], i+1
    if kind=="br4": return struct.unpack_from("<i",code,i)[0], i+4
    if kind=="switch":
        n=struct.unpack_from("<I",code,i)[0]; i+=4
        vals=list(struct.unpack_from("<"+"i"*n,code,i)) if n else []
        return vals, i+4*n
    return None,i

def _decode_cil(code, pe=None):
    out=[]; i=0
    while i < len(code):
        off=i; b=code[i]; i+=1
        if b==0xfe and i<len(code):
            b2=code[i]; i+=1
            name,kind=_IL_TWO.get(b2,("unknown.fe%02x"%b2,"none"))
        else:
            name,kind=_IL_ONE.get(b,("unknown.%02x"%b,"none"))
        try: operand,i=_cil_operand(code,i,kind)
        except Exception: operand=None
        text=None
        end=i
        if name=="ldstr" and pe is not None:
            text=_dotnet_user_string(pe, operand)
        elif name in ("call","callvirt","newobj") and pe is not None:
            text=_dotnet_resolve_method_token(pe, operand)
        target=None
        if kind in ("br1","br4") and isinstance(operand,int):
            target=end+operand
        elif kind=="switch" and isinstance(operand,list):
            target=[end+x for x in operand]
        out.append({"off":off,"end":end,"size":end-off,"op":name,"operand":operand,
                    "target":target,"text":text})
    return out

def _method_il_bytes(pe, mrow):
    try: rva=int(mrow.Rva)
    except Exception:
        try: rva=int(mrow.RVA)
        except Exception: return None
    if not rva: return None
    try: off=pe.get_offset_from_rva(rva)
    except Exception: return None
    try:
        data=pe.__data__
        b0=data[off]
        # Tiny header: low two bits == 2, code size in upper six bits.
        if (b0 & 0x3)==0x2:
            sz=b0>>2
            return data[off+1:off+1+sz]
        # Fat header: low two bits == 3, header size in dwords in high nibble.
        import struct
        flags_size=struct.unpack_from("<H",data,off)[0]
        if (flags_size & 0x3)!=0x3: return None
        hdr_dwords=(flags_size >> 12) & 0xf
        hdr_size=hdr_dwords*4
        code_size=struct.unpack_from("<I",data,off+4)[0]
        return data[off+hdr_size:off+hdr_size+code_size]
    except Exception:
        return None

class DotNetILFrontend:
    """Runtime-specific frontend for managed .NET assemblies.

    This is intentionally a frontend boundary, not a CoreCLR-native hack.  It
    finds the managed payload, decodes enough CIL/metadata for useful reports and
    simple challenge-style solve candidates, and provides a clean place to grow a
    full IL symbolic executor later.
    """
    SOURCE_CALLS=("Console::ReadLine","Environment::GetEnvironmentVariable","File::ReadAllText",
                  "File::ReadAllBytes","Registry::GetValue","RegistryKey::GetValue")
    COMPARE_CALLS=("String::Equals","String::op_Equality","String::Compare","SequenceEqual","StartsWith","EndsWith","Contains")
    SINK_CALLS=("Console::WriteLine","MessageBox::Show","Environment::Exit")

    def __init__(self, binary, rt=None, explicit_assembly=None, method_filter=None,
                 il_dump=False, il_plan_patch=False):
        self.binary=binary; self.rt=rt or {}; self.explicit_assembly=explicit_assembly
        self.method_filter=method_filter; self.il_dump=il_dump; self.il_plan_patch=il_plan_patch
        self.assemblies=_dotnet_payload_candidates(binary,self.rt, explicit=explicit_assembly)
        self.primary=self.assemblies[0] if self.assemblies else None
        self.pe=None; self.dnfile_error=None; self.raw=[]; self.methods=[]

    def _load_dnfile(self):
        if not self.primary: return False
        try:
            import dnfile
            self.pe=dnfile.dnPE(self.primary, clr_lazy_load=False)
            if not getattr(self.pe,"net",None):
                self.dnfile_error="file has no CLR metadata"
                return False
            return True
        except Exception as e:
            self.dnfile_error=str(e)
            return False

    def _load(self):
        if self.primary:
            self.raw=_raw_strings(_read_file_prefix(self.primary, 32*1024*1024))
        ok=self._load_dnfile()
        if ok: self.methods=self._decode_methods()
        return ok

    def _decode_methods(self, limit=5000):
        out=[]
        try: rows=self.pe.net.mdtables.MethodDef.rows
        except Exception: return out
        for idx,m in enumerate(rows[:limit],1):
            name=_safe_name(getattr(m,"Name",None)) or ("method_%d"%idx)
            code=_method_il_bytes(self.pe,m)
            if not code: continue
            ins=_decode_cil(code,self.pe)
            strings=[x["text"] for x in ins if x["op"]=="ldstr" and x.get("text")]
            calls=[x["text"] for x in ins if x["op"] in ("call","callvirt","newobj") and x.get("text")]
            if strings or calls:
                out.append({"name":name,"strings":strings,"calls":calls,"ins":ins})
        return out

    def _looks_like_identifier_noise(self, st):
        # .NET async state-machine/generated member names often contain words
        # like success/welcome/failed but are not user-visible outcome strings.
        if not st: return True
        if any(x in st for x in ("<", ">d__", ">b__", "::", "+<")): return True
        if st.count(".") >= 2 and " " not in st: return True
        if len(st) > 120: return True
        return False

    def _classify_strings(self, strings):
        wins=[]; loses=[]; other=[]
        for st in strings:
            low=st.lower()
            if self._looks_like_identifier_noise(st):
                other.append(st); continue
            # Negative phrases win precedence: e.g. "checksum is not correct"
            # must not be classified as a success just because it contains
            # the word "correct".
            if any(w in low for w in LOSE_WORDS): loses.append(st)
            elif any(w in low for w in WIN_WORDS): wins.append(st)
            else: other.append(st)
        return wins,loses,other

    def _matching_methods(self):
        if not self.method_filter:
            return list(self.methods)
        import re
        try:
            rx=re.compile(self.method_filter, re.I)
            return [m for m in self.methods if rx.search(m["name"])]
        except Exception:
            f=self.method_filter.lower()
            return [m for m in self.methods if f in m["name"].lower()]

    def _format_il(self, ins):
        op=ins["op"]
        if ins.get("text") is not None:
            if op=="ldstr": return "IL_%04x: %-12s %r" % (ins["off"], op, ins["text"])
            return "IL_%04x: %-12s %s" % (ins["off"], op, ins["text"])
        if ins.get("target") is not None:
            t=ins["target"]
            if isinstance(t,list):
                return "IL_%04x: %-12s %s" % (ins["off"], op, ", ".join("IL_%04x"%x for x in t))
            return "IL_%04x: %-12s IL_%04x" % (ins["off"], op, t)
        if ins.get("operand") is not None:
            return "IL_%04x: %-12s %r" % (ins["off"], op, ins["operand"])
        return "IL_%04x: %s" % (ins["off"], op)

    def _dump_methods(self, methods, max_methods=8, max_ins=220):
        if not methods: return
        hr(".NET IL METHOD DUMP")
        for m in methods[:max_methods]:
            print("  method: %s" % m["name"])
            shown=0
            for ins in m["ins"]:
                print("    "+self._format_il(ins)); shown+=1
                if shown>=max_ins:
                    print("    ... %d more instruction(s)" % (len(m["ins"])-shown)); break
            print()
        if len(methods)>max_methods:
            print("  ... %d more matching method(s); narrow with --il-method" % (len(methods)-max_methods))

    def _constraint_shapes(self, methods):
        """Report source/compare/string shapes without claiming a solved input.
        This is intentionally explanatory: the full IL symbolic interpreter can
        grow behind this method later."""
        rows=[]
        for m in methods:
            calls="\n".join(m["calls"])
            source=[c for c in m["calls"] if any(x in c for x in self.SOURCE_CALLS)]
            compare=[c for c in m["calls"] if any(x in c for x in self.COMPARE_CALLS)]
            wins,loses,other=self._classify_strings(m["strings"])
            ops=[x["op"] for x in m["ins"]]
            arith=[op for op in ops if op in ("xor","add","sub","mul","and","or","ceq","cgt","clt","ldelem.u1","ldelem.u2","ldlen")]
            if source or compare or wins or loses or arith:
                rows.append((m,source,compare,wins,loses,arith,other))
        if not rows: return
        hr(".NET IL CONSTRAINT SHAPES (non-destructive)")
        for m,source,compare,wins,loses,arith,other in rows[:12]:
            print("  method: %s" % m["name"])
            if source: print("    sources : %s" % ", ".join(source[:4]))
            if compare: print("    compares: %s" % ", ".join(compare[:4]))
            if arith: print("    ops     : %s" % ", ".join(sorted(set(arith))[:10]))
            consts=[x for x in other if not self._looks_like_identifier_noise(x) and "://" not in x]
            if consts: print("    consts  : %s" % ", ".join(repr(x) for x in consts[:5]))
            if wins: print("    win-ish : %s" % ", ".join(repr(x) for x in wins[:3]))
            if loses: print("    lose-ish: %s" % ", ".join(repr(x) for x in loses[:3]))
        if len(rows)>12:
            print("  ... %d more method(s); narrow with --il-method" % (len(rows)-12))

    def _patch_plan(self, methods):
        """Dry-run IL branch rewrite plan. Does not modify assemblies."""
        hr(".NET IL PATCH PLAN (dry-run; no bytes written)")
        any_plan=False
        cond_prefix=("brfalse","brtrue","beq","bne.un","bge","bgt","ble","blt")
        for m in methods:
            wins,loses,other=self._classify_strings(m["strings"])
            calls="\n".join(m["calls"])
            interesting = wins or loses or any(x in calls for x in self.COMPARE_CALLS) or any(x in calls for x in self.SOURCE_CALLS)
            if not interesting: continue
            branches=[ins for ins in m["ins"] if any(ins["op"].startswith(p) for p in cond_prefix)]
            if not branches: continue
            any_plan=True
            print("  method: %s" % m["name"])
            if wins: print("    win-ish strings : %s" % ", ".join(repr(x) for x in wins[:3]))
            if loses: print("    lose-ish strings: %s" % ", ".join(repr(x) for x in loses[:3]))
            for br in branches[:12]:
                fall=br.get("end")
                tgt=br.get("target")
                print("    branch %s -> target %s, fallthrough IL_%04x" %
                      (self._format_il(br), ("IL_%04x"%tgt if isinstance(tgt,int) else repr(tgt)), fall))
                print("      dry-run options: force fallthrough (NOP branch) OR force target (replace with unconditional br)")
            if len(branches)>12:
                print("    ... %d more conditional branch(es)" % (len(branches)-12))
        if not any_plan:
            print("  no IL conditional branches found near source/compare/outcome logic")
        print("  status: plan only. IL assembly rewriting is not performed by this tool.")
        return any_plan

    def report(self):
        hr(".NET IL FRONTEND (managed payload analysis)")
        if not self.assemblies:
            print("  no managed .NET assembly payload found next to the runtime host")
            print("  hint: pass the managed .dll/.exe directly, or inspect --mode runtime-report artifacts")
            return False
        print("  selected assembly : %s" % self.primary)
        if len(self.assemblies)>1:
            print("  other assemblies  : %d candidate(s)" % (len(self.assemblies)-1))
            for pth in self.assemblies[1:8]: print("    - "+pth)
        ok=self._load()
        wins,loses,other=self._classify_strings(self.raw)
        print("  metadata parser   : %s" % ("dnfile" if ok else "raw strings only"))
        if self.dnfile_error:
            print("  parser note       : %s" % self.dnfile_error)
            print("  install hint      : %s -m pip install dnfile" % sys.executable)
        print("  raw strings       : %d printable/UTF-16 string(s)" % len(self.raw))
        if wins or loses:
            print("  outcome strings   : win=%d lose=%d" % (len(wins),len(loses)))
            for st in (wins[:5]+loses[:5]): print("    - %r" % st)
        if ok:
            source_methods=[]; compare_methods=[]; sink_methods=[]
            for m in self.methods:
                calls="\n".join(m["calls"])
                if any(x in calls for x in self.SOURCE_CALLS): source_methods.append(m)
                if any(x in calls for x in self.COMPARE_CALLS): compare_methods.append(m)
                if any(x in calls for x in self.SINK_CALLS): sink_methods.append(m)
            print("  decoded methods   : %d method(s) with calls/strings" % len(self.methods))
            print("  source methods    : %d" % len(source_methods))
            print("  compare methods   : %d" % len(compare_methods))
            print("  sink methods      : %d" % len(sink_methods))
            for label,arr in (("source",source_methods),("compare",compare_methods),("sink",sink_methods)):
                for m in arr[:4]: print("    %s: %s" % (label,m["name"]))
            selected=self._matching_methods()
            if self.method_filter:
                print("  method filter    : %r -> %d method(s)" % (self.method_filter, len(selected)))
            if self.method_filter or self.il_dump or self.il_plan_patch:
                self._constraint_shapes(selected)
            if self.il_dump:
                self._dump_methods(selected)
            if self.il_plan_patch:
                self._patch_plan(selected)
        print("  note             : this frontend handles managed IL; native angr remains the frontend for non-IL targets")
        return ok

    def solve(self):
        ok=self.report()
        hr(".NET IL SOLVE (bounded managed-string candidate extraction)")
        if not ok:
            print("  no IL metadata decoder available; cannot solve at IL level")
            return False
        selected=self._matching_methods()
        self._constraint_shapes(selected)
        candidates=[]
        for m in selected:
            calls="\n".join(m["calls"])
            has_cmp=any(x in calls for x in self.COMPARE_CALLS)
            has_src=any(x in calls for x in self.SOURCE_CALLS)
            wins,loses,other=self._classify_strings(m["strings"])
            # Common CTF/challenge shape: read input, compare to ldstr constant,
            # then print/return success/failure.  We only emit constants that are
            # not themselves obvious outcome messages.
            if has_cmp and (has_src or wins or loses):
                for st in other:
                    if st == m["name"] or "://" in st: continue
                    if self._looks_like_identifier_noise(st): continue
                    if 1 <= len(st) <= 128 and all((c=="\t" or c=="\n" or 32 <= ord(c) < 127) for c in st):
                        score=(3 if has_src else 0)+(2 if wins else 0)+(2 if loses else 0)+min(3,len(st)//8)
                        candidates.append((score,m["name"],st,wins[:2],loses[:2]))
        if not candidates:
            print("  no direct String.Equals/op_Equality-style candidate isolated")
            print("  next step: implement the full IL symbolic executor over this frontend")
            return False
        candidates.sort(reverse=True, key=lambda x:(x[0],len(x[2])))
        print("  constants near managed source/compare/outcome logic (unverified):")
        seen=set(); n=0
        for score,mn,st,w,l in candidates:
            if st in seen: continue
            seen.add(st); n+=1
            print("    %2d. %r   method=%s score=%d" % (n, st, mn, score))
            if w: print("        nearby win : %s" % ", ".join(repr(x) for x in w))
            if l: print("        nearby lose: %s" % ", ".join(repr(x) for x in l))
            if n>=10: break
        print("  status: candidates are static IL-derived and not runtime-verified")
        return True

    def patch(self, out_arg=None):
        old_plan=self.il_plan_patch
        self.il_plan_patch=False  # avoid printing the same plan twice in --mode patch
        ok=self.report()
        self.il_plan_patch=old_plan
        if not ok:
            hr(".NET IL PATCH PLAN")
            print("  no IL metadata decoder available; cannot plan IL branch rewrites")
            return False
        # Non-destructive by design: produce an IL rewrite plan, not a modified
        # third-party assembly.  Native patching remains in the angr backend.
        return self._patch_plan(self._matching_methods())

def select_runtime_frontend(kind, binary, rt, explicit_assembly=None,
                            method_filter=None, il_dump=False, il_plan_patch=False):
    if kind in ("dotnet-apphost","dotnet-managed"):
        return DotNetILFrontend(binary, rt, explicit_assembly=explicit_assembly,
                                method_filter=method_filter, il_dump=il_dump,
                                il_plan_patch=il_plan_patch)
    return None

