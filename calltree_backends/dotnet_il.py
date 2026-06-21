#!/usr/bin/env python3
"""Standalone .NET IL frontend for Ariadne.

This backend is intentionally managed-code-aware. It analyzes CLI metadata and
CIL directly instead of asking angr to execute CoreCLR bootstrap code.
Patch mode emits dry-run plans by default; write-capable method-body replacement
is opt-in
"""
import os
import sys

from calltree_backends.frontend import AnalyzerFrontend, AnalyzerOptions
from calltree_backends.outcomes import WIN_WORDS, LOSE_WORDS
from calltree_backends.util import hr, read_file_prefix as _read_file_prefix, glob_limited as _glob_limited

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

def _method_body_info(pe, mrow):
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
            return {"rva":rva,"header_off":off,"code_off":off+1,"code_size":sz,
                    "header_size":1,"tiny":True,"more_sects":False,
                    "code":data[off+1:off+1+sz]}
        # Fat header: low two bits == 3, header size in dwords in high nibble.
        import struct
        flags_size=struct.unpack_from("<H",data,off)[0]
        if (flags_size & 0x3)!=0x3: return None
        hdr_dwords=(flags_size >> 12) & 0xf
        hdr_size=hdr_dwords*4
        code_size=struct.unpack_from("<I",data,off+4)[0]
        return {"rva":rva,"header_off":off,"code_off":off+hdr_size,
                "code_size":code_size,"header_size":hdr_size,"tiny":False,
                "more_sects":bool(flags_size & 0x8),
                "code":data[off+hdr_size:off+hdr_size+code_size]}
    except Exception:
        return None

def _method_il_bytes(pe, mrow):
    info=_method_body_info(pe,mrow)
    return info.get("code") if info else None

class DotNetILFrontend(AnalyzerFrontend):
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

    def __init__(self, binary, rt=None, options=None):
        self.options=options or AnalyzerOptions()
        self.binary=binary; self.rt=rt or {}; self.explicit_assembly=self.options.il_assembly
        self.method_filter=self.options.method_filter; self.il_dump=self.options.il_dump
        self.il_plan_patch=self.options.il_plan_patch; self.write_patch=self.options.write_patch
        self.il_patch_return=self.options.il_return
        self.assemblies=_dotnet_payload_candidates(binary,self.rt, explicit=self.explicit_assembly)
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
            body=_method_body_info(self.pe,m)
            if not body or not body.get("code"): continue
            code=body["code"]
            ins=_decode_cil(code,self.pe)
            strings=[x["text"] for x in ins if x["op"]=="ldstr" and x.get("text")]
            calls=[x["text"] for x in ins if x["op"] in ("call","callvirt","newobj") and x.get("text")]
            if strings or calls or any(x["op"].startswith(("br","bne","beq")) for x in ins):
                out.append({"name":name,"row":m,"body":body,"strings":strings,"calls":calls,"ins":ins})
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
            print("  ... %d more matching method(s); narrow with --method" % (len(methods)-max_methods))

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
            print("  ... %d more method(s); narrow with --method" % (len(rows)-12))

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

    def _v_int(self,n): return {"k":"int","v":int(n)}
    def _v_str(self,s): return {"k":"str","v":s}
    def _v_symstr(self,name="arg0"): return {"k":"symstr","name":name}
    def _v_strlen(self,s): return {"k":"strlen","s":s}
    def _v_char(self,s,i): return {"k":"char","s":s,"i":i}
    def _v_xor(self,a,b): return {"k":"xor","a":a,"b":b}
    def _v_cond(self,op,*args): return {"k":"cond","op":op,"args":args}

    def _is_true_const(self,v): return v and v.get("k")=="int" and int(v.get("v",0))!=0
    def _is_false_const(self,v): return v and v.get("k")=="int" and int(v.get("v",0))==0

    def _copy_state(self,st):
        return {"pc":st["pc"], "stack":list(st["stack"]), "locals":dict(st["locals"]),
                "constraints":list(st["constraints"]), "steps":st.get("steps",0)}

    def _add_cond(self,st,cond,truth=True):
        if cond is None: return False
        if cond.get("k")=="int":
            return (truth and self._is_true_const(cond)) or ((not truth) and self._is_false_const(cond))
        if cond.get("k")!="cond":
            st["constraints"].append(("truthy" if truth else "falsy", cond)); return True
        op=cond["op"]; args=cond["args"]
        if op=="not": return self._add_cond(st,args[0],not truth)
        if op=="isnullorempty":
            s=args[0]
            st["constraints"].append(("len_eq" if truth else "len_ne", s, 0)); return True
        if op=="startswith":
            st["constraints"].append(("prefix" if truth else "not_prefix", args[0], args[1])); return True
        if op=="endswith":
            st["constraints"].append(("suffix" if truth else "not_suffix", args[0], args[1])); return True
        if op=="streq":
            st["constraints"].append(("str_eq" if truth else "str_ne", args[0], args[1])); return True
        if op=="eq":
            st["constraints"].append(("expr_eq" if truth else "expr_ne", args[0], args[1])); return True
        st["constraints"].append(("cond" if truth else "not_cond", cond)); return True

    def _pop(self,st,default=None):
        return st["stack"].pop() if st["stack"] else default

    def _call_model(self, name, st):
        # Known methods only. Unknown calls are treated conservatively as no-op;
        lname=(name or "").lower()
        if "console::writeline" in lname or "console::write" in lname:
            self._pop(st); return None
        if "string::isnullorempty" in lname:
            s=self._pop(st,self._v_symstr()); st["stack"].append(self._v_cond("isnullorempty",s)); return None
        if "string::get_length" in lname:
            s=self._pop(st,self._v_symstr()); st["stack"].append(self._v_strlen(s)); return None
        if "string::get_chars" in lname:
            idx=self._pop(st,self._v_int(0)); s=self._pop(st,self._v_symstr())
            st["stack"].append(self._v_char(s,idx)); return None
        if "string::startswith" in lname:
            prefix=self._pop(st,self._v_str("")); s=self._pop(st,self._v_symstr())
            st["stack"].append(self._v_cond("startswith",s,prefix)); return None
        if "string::endswith" in lname:
            suffix=self._pop(st,self._v_str("")); s=self._pop(st,self._v_symstr())
            st["stack"].append(self._v_cond("endswith",s,suffix)); return None
        if "string::op_equality" in lname or "string::equals" in lname or lname.endswith("::equals"):
            b=self._pop(st,self._v_str("")); a=self._pop(st,self._v_symstr())
            if (a or {}).get("k") in ("symstr","str") or (b or {}).get("k") in ("symstr","str"):
                st["stack"].append(self._v_cond("streq",a,b))
            else:
                st["stack"].append(self._v_cond("eq",a,b))
            return None
        return None

    def _execute_symbolic_method(self,m,max_paths=64,max_steps=800,max_len=96):
        ins=m["ins"]; off_to_idx={x["off"]:i for i,x in enumerate(ins)}
        init={"pc":0,"stack":[],"locals":{},"constraints":[],"steps":0}
        solutions=[]; work=[init]
        while work and len(solutions)<8:
            st=work.pop()
            while 0 <= st["pc"] < len(ins) and st.get("steps",0)<max_steps:
                st["steps"]=st.get("steps",0)+1
                x=ins[st["pc"]]; op=x["op"]; npc=st["pc"]+1
                if op=="nop": st["pc"]=npc; continue
                if op.startswith("ldarg"):
                    # Treat arg0 as the symbolic input string. Other args become symbolic strings too.
                    idx=0
                    if op in ("ldarg.1","ldarg.2","ldarg.3"): idx=int(op[-1])
                    elif op=="ldarg.s": idx=int(x.get("operand") or 0)
                    st["stack"].append(self._v_symstr("arg%d"%idx)); st["pc"]=npc; continue
                if op.startswith("ldloc"):
                    idx=op.split(".")[-1] if op!="ldloc.s" else str(x.get("operand") or 0)
                    st["stack"].append(st["locals"].get(idx,self._v_int(0))); st["pc"]=npc; continue
                if op.startswith("stloc"):
                    idx=op.split(".")[-1] if op!="stloc.s" else str(x.get("operand") or 0)
                    st["locals"][idx]=self._pop(st,self._v_int(0)); st["pc"]=npc; continue
                if op=="ldstr": st["stack"].append(self._v_str(x.get("text") or "")); st["pc"]=npc; continue
                if op.startswith("ldc.i4"):
                    vals={"ldc.i4.m1":-1,"ldc.i4.0":0,"ldc.i4.1":1,"ldc.i4.2":2,"ldc.i4.3":3,"ldc.i4.4":4,
                          "ldc.i4.5":5,"ldc.i4.6":6,"ldc.i4.7":7,"ldc.i4.8":8}
                    st["stack"].append(self._v_int(vals.get(op,x.get("operand") or 0))); st["pc"]=npc; continue
                if op in ("call","callvirt","newobj"):
                    self._call_model(x.get("text"),st); st["pc"]=npc; continue
                if op=="dup":
                    if st["stack"]: st["stack"].append(st["stack"][-1])
                    st["pc"]=npc; continue
                if op=="pop": self._pop(st); st["pc"]=npc; continue
                if op=="xor":
                    b=self._pop(st,self._v_int(0)); a=self._pop(st,self._v_int(0)); st["stack"].append(self._v_xor(a,b)); st["pc"]=npc; continue
                if op in ("add","sub","mul","and","or"):
                    b=self._pop(st,self._v_int(0)); a=self._pop(st,self._v_int(0)); st["stack"].append({"k":op,"a":a,"b":b}); st["pc"]=npc; continue
                if op=="ceq":
                    b=self._pop(st,self._v_int(0)); a=self._pop(st,self._v_int(0)); st["stack"].append(self._v_cond("eq",a,b)); st["pc"]=npc; continue
                if op in ("br.s","br"):
                    tgt=x.get("target"); st["pc"]=off_to_idx.get(tgt,npc); continue
                if op.startswith("brtrue") or op.startswith("brfalse"):
                    cond=self._pop(st,self._v_int(0)); tgt=x.get("target")
                    true_st=self._copy_state(st); false_st=self._copy_state(st)
                    if self._add_cond(true_st,cond,True):
                        true_st["pc"]=off_to_idx.get(tgt,npc) if op.startswith("brtrue") else npc
                        work.append(true_st)
                    if self._add_cond(false_st,cond,False):
                        false_st["pc"]=npc if op.startswith("brtrue") else off_to_idx.get(tgt,npc)
                        work.append(false_st)
                    break
                if op in ("beq","beq.s","bne.un","bne.un.s"):
                    b=self._pop(st,self._v_int(0)); a=self._pop(st,self._v_int(0)); cond=self._v_cond("eq",a,b); tgt=x.get("target")
                    target_on_eq=op.startswith("beq")
                    eq_st=self._copy_state(st); ne_st=self._copy_state(st)
                    if self._add_cond(eq_st,cond,True):
                        eq_st["pc"]=off_to_idx.get(tgt,npc) if target_on_eq else npc; work.append(eq_st)
                    if self._add_cond(ne_st,cond,False):
                        ne_st["pc"]=npc if target_on_eq else off_to_idx.get(tgt,npc); work.append(ne_st)
                    break
                if op=="ret":
                    rv=self._pop(st,self._v_int(0))
                    if self._is_true_const(rv):
                        sol=self._solve_constraints(st["constraints"],max_len=max_len)
                        if sol: solutions.append(sol)
                    break
                st["pc"]=npc
            if len(work)>max_paths: work=work[-max_paths:]
        return solutions

    def _constraint_known_len(self,constraints,name="arg0"):
        for c in constraints:
            if c[0]=="len_eq" and c[1].get("k")=="symstr" and c[1].get("name")==name:
                try: return int(c[2])
                except Exception: pass
            if c[0]=="expr_eq":
                a,b=c[1],c[2]
                for x,y in ((a,b),(b,a)):
                    if x.get("k")=="strlen" and x["s"].get("name")==name and y.get("k")=="int": return int(y["v"])
        return None

    def _solve_constraints(self,constraints,max_len=96):
        try: import z3
        except Exception:
            print("  bounded IL executor needs z3-solver (python -m pip install z3-solver)"); return None
        name="arg0"; n=self._constraint_known_len(constraints,name) or max_len
        n=max(0,min(max_len,n))
        length=z3.Int("len_%s"%name); chars=[z3.BitVec("%s_%02d"%(name,i),16) for i in range(max_len)]
        sol=z3.Solver(); sol.add(length>=0,length<=max_len)
        for ch in chars: sol.add(z3.UGE(ch,0x20), z3.ULE(ch,0x7e))
        def str_name(v): return v.get("name","arg0") if v and v.get("k")=="symstr" else "arg0"
        def concrete_str(v): return v.get("v") if v and v.get("k")=="str" else None
        def int_expr(v):
            if v is None: return z3.IntVal(0)
            if v.get("k")=="int": return z3.IntVal(int(v["v"]))
            if v.get("k")=="strlen": return length
            return None
        def bv_expr(v):
            if v is None: return z3.BitVecVal(0,16)
            if v.get("k")=="int": return z3.BitVecVal(int(v["v"]) & 0xffff,16)
            if v.get("k")=="char":
                idx=v.get("i")
                if isinstance(idx,dict) and idx.get("k")=="int": return chars[int(idx["v"])]
                return chars[0]
            if v.get("k")=="xor": return bv_expr(v["a"]) ^ bv_expr(v["b"])
            if v.get("k") in ("add","sub","mul","and","or"):
                a,b=bv_expr(v["a"]),bv_expr(v["b"])
                return {"add":a+b,"sub":a-b,"mul":a*b,"and":a&b,"or":a|b}[v["k"]]
            return None
        def add_str_eq(sym,concrete,neg=False):
            if concrete is None: return
            if not neg: sol.add(length==len(concrete))
            eqs=[]
            for i,ch in enumerate(concrete[:max_len]): eqs.append(chars[i]==ord(ch))
            sol.add(z3.Not(z3.And(*eqs)) if neg and eqs else z3.And(*eqs))
        for c in constraints:
            op=c[0]
            if op=="len_eq": sol.add(length==int(c[2]))
            elif op=="len_ne": sol.add(length!=int(c[2]))
            elif op=="prefix":
                pref=concrete_str(c[2]) or ""; sol.add(length>=len(pref))
                for i,ch in enumerate(pref[:max_len]): sol.add(chars[i]==ord(ch))
            elif op=="suffix":
                suf=concrete_str(c[2]) or ""; known=self._constraint_known_len(constraints,name)
                if known is not None and known>=len(suf):
                    for i,ch in enumerate(suf): sol.add(chars[known-len(suf)+i]==ord(ch))
            elif op=="str_eq":
                a,b=c[1],c[2]
                add_str_eq(a,concrete_str(b),False) if concrete_str(b) is not None else add_str_eq(b,concrete_str(a),False)
            elif op=="str_ne":
                a,b=c[1],c[2]
                add_str_eq(a,concrete_str(b),True) if concrete_str(b) is not None else add_str_eq(b,concrete_str(a),True)
            elif op in ("expr_eq","expr_ne"):
                a,b=c[1],c[2]
                ia,ib=int_expr(a),int_expr(b)
                if ia is not None and ib is not None:
                    sol.add(ia==ib if op=="expr_eq" else ia!=ib)
                else:
                    ba,bb=bv_expr(a),bv_expr(b)
                    if ba is not None and bb is not None: sol.add(ba==bb if op=="expr_eq" else ba!=bb)
        if sol.check()!=z3.sat: return None
        model=sol.model(); ln=model.eval(length,model_completion=True).as_long(); ln=max(0,min(max_len,ln))
        out=[]
        for i in range(ln): out.append(chr(model.eval(chars[i],model_completion=True).as_long() & 0xff))
        return "".join(out)

    def _run_bounded_symbolic_solver(self,methods):
        hr(".NET IL BOUNDED SYMBOLIC EXECUTOR")
        found=[]
        for m in methods[:24]:
            sols=self._execute_symbolic_method(m)
            for sol in sols:
                if sol not in [x[1] for x in found]:
                    found.append((m["name"],sol))
                    print("  solved candidate: %r   method=%s" % (sol,m["name"]))
        if not found: print("  no satisfiable return-true path found in selected bounded methods")
        return found

    def solve(self):
        ok=self.report()
        hr(".NET IL SOLVE (bounded managed-string candidate extraction)")
        if not ok:
            print("  no IL metadata decoder available; cannot solve at IL level")
            return False
        selected=self._matching_methods()
        self._constraint_shapes(selected)
        self._run_bounded_symbolic_solver(selected)
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

    def _ret_const_before(self, ins, idx):
        j=idx-1
        while j>=0 and ins[j]["op"]=="nop": j-=1
        if j<0: return None
        op=ins[j]["op"]
        if op in ("ldc.i4.0","ldc.i4.1"): return op.endswith("1")
        return None

    def _reachable_method_slice_score(self, m, start_idx, max_steps=240):
        """Score a caller side by reachable win/lose strings and approximate size."""
        ins=m["ins"]; off_to_idx={x["off"]:i for i,x in enumerate(ins)}
        seen=set(); stack=[start_idx]; strings=[]; count=0; rets=[]
        while stack and count<max_steps:
            i=stack.pop()
            if i in seen or i<0 or i>=len(ins): continue
            seen.add(i); count+=1
            x=ins[i]
            if x["op"]=="ldstr" and x.get("text"): strings.append(x["text"])
            if x["op"]=="ret":
                rv=self._ret_const_before(ins,i)
                if rv is not None: rets.append(rv)
                continue
            op=x["op"]; nxt=i+1
            if op in ("br.s","br"):
                stack.append(off_to_idx.get(x.get("target"),nxt)); continue
            if op.startswith(("brtrue","brfalse","beq","bne.un","bge","bgt","ble","blt")):
                stack.append(nxt); stack.append(off_to_idx.get(x.get("target"),nxt)); continue
            stack.append(nxt)
        wins,loses,_=self._classify_strings(strings)
        score=10*len(wins)-10*len(loses)+count/100.0
        return {"score":score,"wins":wins,"loses":loses,"count":count,"rets":rets}

    def _method_return_value_scores(self, m):
        """Infer a desirable bool return from the selected method's own exits."""
        scores={True:0.0, False:0.0}; reasons=[]; ins=m["ins"]
        for i,x in enumerate(ins):
            if x["op"]!="ret": continue
            rv=self._ret_const_before(ins,i)
            if rv is None: continue
            # Look back within the local basic-block-ish window for outcome strings.
            strings=[]; j=i-1; window=0
            while j>=0 and window<18:
                if ins[j]["op"].startswith(("br","beq","bne","bge","bgt","ble","blt")) and window>0: break
                if ins[j]["op"]=="ldstr" and ins[j].get("text"): strings.append(ins[j]["text"])
                j-=1; window+=1
            wins,loses,_=self._classify_strings(strings)
            delta=1.0 + 12.0*len(wins) - 12.0*len(loses)
            scores[rv]+=delta
            if wins or loses:
                reasons.append("%s return at IL_%04x near win=%s lose=%s -> %+g" %
                               (rv, x["off"], [w for w in wins[:2]], [l for l in loses[:2]], delta))
            else:
                reasons.append("%s return at IL_%04x -> %+g" % (rv, x["off"], delta))
        return scores,reasons

    def _caller_return_value_scores(self, target_name):
        """Infer which bool return unlocks callers by inspecting call; brtrue/brfalse."""
        scores={True:0.0, False:0.0}; reasons=[]
        t=target_name.lower()
        for m in self.methods:
            ins=m["ins"]; off_to_idx={x["off"]:i for i,x in enumerate(ins)}
            for i,x in enumerate(ins[:-1]):
                if x["op"] not in ("call","callvirt") or not x.get("text"): continue
                cname=x["text"].split("::")[-1].lower()
                if cname!=t: continue
                # direct bool use: call; brtrue/brfalse next instruction
                j=i+1
                while j<len(ins) and ins[j]["op"]=="nop": j+=1
                if j>=len(ins): continue
                br=ins[j]
                if not (br["op"].startswith("brtrue") or br["op"].startswith("brfalse")): continue
                target_idx=off_to_idx.get(br.get("target"), j+1)
                fall_idx=j+1
                target_score=self._reachable_method_slice_score(m,target_idx)
                fall_score=self._reachable_method_slice_score(m,fall_idx)
                if br["op"].startswith("brtrue"):
                    true_side=false_side=target_score
                    false_side=fall_score
                else:
                    false_side=target_score
                    true_side=fall_score
                # Prefer win/lose classification. Size is only a tiny tiebreaker.
                scores[True]+=true_side["score"]; scores[False]+=false_side["score"]
                reasons.append("caller %s IL_%04x %s: true_score=%.2f false_score=%.2f" %
                               (m["name"], br["off"], br["op"], true_side["score"], false_side["score"]))
        return scores,reasons

    def _infer_bool_patch_return(self, m):
        own,own_reasons=self._method_return_value_scores(m)
        caller,caller_reasons=self._caller_return_value_scores(m["name"])
        scores={True:own[True]+caller[True], False:own[False]+caller[False]}
        reasons=own_reasons+caller_reasons
        print("  IL return inference for %s:" % m["name"])
        print("    true score : %.2f" % scores[True])
        print("    false score: %.2f" % scores[False])
        for r in reasons[:10]: print("    - "+r)
        if scores[True]==scores[False]: return None
        return True if scores[True]>scores[False] else False

    def _write_return_patch(self,methods,out_arg=None):
        if not self.write_patch:
            print("  IL patch write: disabled; add --write-patch for method-body replacement")
            return False
        if len(methods)!=1:
            print("  IL patch write: refusing because --method matched %d methods; use an exact filter" % len(methods))
            return False
        m=methods[0]; body=m.get("body") or {}
        if body.get("more_sects"):
            print("  IL patch write: refusing method with extra EH/section metadata")
            return False
        code_size=int(body.get("code_size") or 0); code_off=int(body.get("code_off") or 0)
        ret_choice=self.il_patch_return
        if ret_choice=="auto":
            inferred=self._infer_bool_patch_return(m)
            if inferred is None:
                print("  IL patch write: could not infer the desired bool return; rerun with --patch-return true|false")
                return False
            ret_choice="true" if inferred else "false"
        patch = bytes([0x17 if ret_choice=="true" else 0x16, 0x2a])  # ldc.i4.1/0 ; ret
        if code_size < len(patch):
            print("  IL patch write: method body too small")
            return False
        data=bytearray(_read_file_prefix(self.primary, 1<<30))
        data[code_off:code_off+len(patch)] = patch
        for i in range(code_off+len(patch), code_off+code_size): data[i]=0x00  # nop padding
        out=out_arg or (self.primary+".patched")
        parent=os.path.dirname(out)
        if parent: os.makedirs(parent, exist_ok=True)
        with open(out,"wb") as f: f.write(data)
        print("  IL patch write: method %s -> return %s" % (m["name"], ret_choice))
        print("  wrote %s (original untouched)" % out)
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
        methods=self._matching_methods()
        planned=self._patch_plan(methods)
        if self.write_patch:
            return self._write_return_patch(methods,out_arg=out_arg)
        return planned

def select_runtime_frontend(kind, binary, rt, options=None):
    if kind in ("dotnet-apphost","dotnet-managed"):
        return DotNetILFrontend(binary, rt, options=options)
    return None

