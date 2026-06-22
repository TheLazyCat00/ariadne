#!/usr/bin/env python3
"""Standalone .NET IL frontend for Ariadne.

This backend is intentionally managed-code-aware. It analyzes CLI metadata and
CIL directly instead of asking angr to execute CoreCLR bootstrap code.
Patch mode rewrites failure-only conditional branches in place (stack-balanced
`pop`+`nop`) toward the win side; --mode plan-patch shows a non-destructive preview.
"""
import os
import sys

from calltree_backends.frontend import AnalyzerFrontend, AnalyzerOptions
from calltree_backends.outcomes import WIN_WORDS, LOSE_WORDS
from calltree_backends.util import hr, read_file_prefix as _read_file_prefix, glob_limited as _glob_limited
from calltree_backends.gates import GateCandidate, significance, pick_licensed, render_plan

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

# Full ECMA-335 CIL opcode map (single-byte plus the 0xFE two-byte family).
# Completeness matters for more than pretty disassembly: every opcode must
# declare its operand size so the linear decoder stays in sync.  A missing
# entry would fall back to a zero-length operand and silently misread every
# instruction after it in the method (the operand bytes get decoded as
# opcodes).  Operand kinds: none / u1 / u2 / i1 / i4 / i8 / r4 / r8 /
# token (4-byte metadata or string token) / br1 / br4 (branch displacements) /
# switch (uint32 count followed by that many int32 targets).
_IL_ONE={
  0x00:("nop","none"),0x01:("break","none"),
  0x02:("ldarg.0","none"),0x03:("ldarg.1","none"),0x04:("ldarg.2","none"),0x05:("ldarg.3","none"),
  0x06:("ldloc.0","none"),0x07:("ldloc.1","none"),0x08:("ldloc.2","none"),0x09:("ldloc.3","none"),
  0x0a:("stloc.0","none"),0x0b:("stloc.1","none"),0x0c:("stloc.2","none"),0x0d:("stloc.3","none"),
  0x0e:("ldarg.s","u1"),0x0f:("ldarga.s","u1"),0x10:("starg.s","u1"),0x11:("ldloc.s","u1"),0x12:("ldloca.s","u1"),0x13:("stloc.s","u1"),
  0x14:("ldnull","none"),0x15:("ldc.i4.m1","none"),0x16:("ldc.i4.0","none"),0x17:("ldc.i4.1","none"),0x18:("ldc.i4.2","none"),
  0x19:("ldc.i4.3","none"),0x1a:("ldc.i4.4","none"),0x1b:("ldc.i4.5","none"),0x1c:("ldc.i4.6","none"),0x1d:("ldc.i4.7","none"),
  0x1e:("ldc.i4.8","none"),0x1f:("ldc.i4.s","i1"),0x20:("ldc.i4","i4"),0x21:("ldc.i8","i8"),0x22:("ldc.r4","r4"),0x23:("ldc.r8","r8"),
  0x25:("dup","none"),0x26:("pop","none"),0x27:("jmp","token"),0x28:("call","token"),0x29:("calli","token"),0x2a:("ret","none"),
  0x2b:("br.s","br1"),0x2c:("brfalse.s","br1"),0x2d:("brtrue.s","br1"),
  0x2e:("beq.s","br1"),0x2f:("bge.s","br1"),0x30:("bgt.s","br1"),0x31:("ble.s","br1"),0x32:("blt.s","br1"),0x33:("bne.un.s","br1"),
  0x34:("bge.un.s","br1"),0x35:("bgt.un.s","br1"),0x36:("ble.un.s","br1"),0x37:("blt.un.s","br1"),
  0x38:("br","br4"),0x39:("brfalse","br4"),0x3a:("brtrue","br4"),0x3b:("beq","br4"),0x3c:("bge","br4"),0x3d:("bgt","br4"),
  0x3e:("ble","br4"),0x3f:("blt","br4"),0x40:("bne.un","br4"),0x41:("bge.un","br4"),0x42:("bgt.un","br4"),0x43:("ble.un","br4"),
  0x44:("blt.un","br4"),0x45:("switch","switch"),
  0x46:("ldind.i1","none"),0x47:("ldind.u1","none"),0x48:("ldind.i2","none"),0x49:("ldind.u2","none"),0x4a:("ldind.i4","none"),
  0x4b:("ldind.u4","none"),0x4c:("ldind.i8","none"),0x4d:("ldind.i","none"),0x4e:("ldind.r4","none"),0x4f:("ldind.r8","none"),
  0x50:("ldind.ref","none"),0x51:("stind.ref","none"),0x52:("stind.i1","none"),0x53:("stind.i2","none"),0x54:("stind.i4","none"),
  0x55:("stind.i8","none"),0x56:("stind.r4","none"),0x57:("stind.r8","none"),
  0x58:("add","none"),0x59:("sub","none"),0x5a:("mul","none"),0x5b:("div","none"),0x5c:("div.un","none"),0x5d:("rem","none"),
  0x5e:("rem.un","none"),0x5f:("and","none"),0x60:("or","none"),0x61:("xor","none"),0x62:("shl","none"),0x63:("shr","none"),
  0x64:("shr.un","none"),0x65:("neg","none"),0x66:("not","none"),
  0x67:("conv.i1","none"),0x68:("conv.i2","none"),0x69:("conv.i4","none"),0x6a:("conv.i8","none"),0x6b:("conv.r4","none"),
  0x6c:("conv.r8","none"),0x6d:("conv.u4","none"),0x6e:("conv.u8","none"),
  0x6f:("callvirt","token"),0x70:("cpobj","token"),0x71:("ldobj","token"),0x72:("ldstr","token"),0x73:("newobj","token"),
  0x74:("castclass","token"),0x75:("isinst","token"),0x76:("conv.r.un","none"),0x79:("unbox","token"),0x7a:("throw","none"),
  0x7b:("ldfld","token"),0x7c:("ldflda","token"),0x7d:("stfld","token"),0x7e:("ldsfld","token"),0x7f:("ldsflda","token"),
  0x80:("stsfld","token"),0x81:("stobj","token"),
  0x82:("conv.ovf.i1.un","none"),0x83:("conv.ovf.i2.un","none"),0x84:("conv.ovf.i4.un","none"),0x85:("conv.ovf.i8.un","none"),
  0x86:("conv.ovf.u1.un","none"),0x87:("conv.ovf.u2.un","none"),0x88:("conv.ovf.u4.un","none"),0x89:("conv.ovf.u8.un","none"),
  0x8a:("conv.ovf.i.un","none"),0x8b:("conv.ovf.u.un","none"),
  0x8c:("box","token"),0x8d:("newarr","token"),0x8e:("ldlen","none"),0x8f:("ldelema","token"),
  0x90:("ldelem.i1","none"),0x91:("ldelem.u1","none"),0x92:("ldelem.i2","none"),0x93:("ldelem.u2","none"),0x94:("ldelem.i4","none"),
  0x95:("ldelem.u4","none"),0x96:("ldelem.i8","none"),0x97:("ldelem.i","none"),0x98:("ldelem.r4","none"),0x99:("ldelem.r8","none"),
  0x9a:("ldelem.ref","none"),0x9b:("stelem.i","none"),0x9c:("stelem.i1","none"),0x9d:("stelem.i2","none"),0x9e:("stelem.i4","none"),
  0x9f:("stelem.i8","none"),0xa0:("stelem.r4","none"),0xa1:("stelem.r8","none"),0xa2:("stelem.ref","none"),
  0xa3:("ldelem","token"),0xa4:("stelem","token"),0xa5:("unbox.any","token"),
  0xb3:("conv.ovf.i1","none"),0xb4:("conv.ovf.u1","none"),0xb5:("conv.ovf.i2","none"),0xb6:("conv.ovf.u2","none"),
  0xb7:("conv.ovf.i4","none"),0xb8:("conv.ovf.u4","none"),0xb9:("conv.ovf.i8","none"),0xba:("conv.ovf.u8","none"),
  0xc2:("refanyval","token"),0xc3:("ckfinite","none"),0xc6:("mkrefany","token"),0xd0:("ldtoken","token"),
  0xd1:("conv.u2","none"),0xd2:("conv.u1","none"),0xd3:("conv.i","none"),0xd4:("conv.ovf.i","none"),0xd5:("conv.ovf.u","none"),
  0xd6:("add.ovf","none"),0xd7:("add.ovf.un","none"),0xd8:("mul.ovf","none"),0xd9:("mul.ovf.un","none"),0xda:("sub.ovf","none"),
  0xdb:("sub.ovf.un","none"),0xdc:("endfinally","none"),0xdd:("leave","br4"),0xde:("leave.s","br1"),0xdf:("stind.i","none"),
  0xe0:("conv.u","none"),
}
_IL_TWO={
  0x00:("arglist","none"),0x01:("ceq","none"),0x02:("cgt","none"),0x03:("cgt.un","none"),0x04:("clt","none"),0x05:("clt.un","none"),
  0x06:("ldftn","token"),0x07:("ldvirtftn","token"),
  0x09:("ldarg","u2"),0x0a:("ldarga","u2"),0x0b:("starg","u2"),0x0c:("ldloc","u2"),0x0d:("ldloca","u2"),0x0e:("stloc","u2"),
  0x0f:("localloc","none"),0x11:("endfilter","none"),0x12:("unaligned.","u1"),0x13:("volatile.","none"),0x14:("tail.","none"),
  0x15:("initobj","token"),0x16:("constrained.","token"),0x17:("cpblk","none"),0x18:("initblk","none"),0x19:("no.","u1"),
  0x1a:("rethrow","none"),0x1c:("sizeof","token"),0x1d:("refanytype","none"),0x1e:("readonly.","none"),
}

def _cil_operand(code, i, kind):
    import struct
    if kind=="none": return None,i
    if kind=="u1": return code[i], i+1
    if kind=="u2": return struct.unpack_from("<H",code,i)[0], i+2
    if kind=="i1": return struct.unpack_from("b",code,i)[0], i+1
    if kind=="i4": return struct.unpack_from("<i",code,i)[0], i+4
    if kind=="i8": return struct.unpack_from("<q",code,i)[0], i+8
    if kind=="r4": return struct.unpack_from("<f",code,i)[0], i+4
    if kind=="r8": return struct.unpack_from("<d",code,i)[0], i+8
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
            # An unrecognized 0xFE opcode is an undefined slot; we cannot know
            # its operand length, so decoding cannot safely continue past it.
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
    # Conditional branch opcodes (short and long forms share these prefixes).
    COND_BRANCH_PREFIX=("brtrue","brfalse","beq","bne.un","bge","bgt","ble","blt")
    FLIP_MARGIN_MIN=5.0     # min slice-score separation to call a branch failure-only

    def __init__(self, binary, rt=None, options=None):
        self.options=options or AnalyzerOptions()
        self.binary=binary; self.rt=rt or {}; self.explicit_assembly=self.options.il_assembly
        self.method_filter=self.options.method_filter; self.il_dump=self.options.il_dump
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
        """Non-destructive branch-flip preview (driven by --mode plan-patch):
        exactly the branches a `--mode patch` run would rewrite, plus the ones it
        must skip. No bytes are written."""
        hr(".NET IL BRANCH-FLIP PLAN (preview; no bytes written)")
        flips,skipped=self._branch_flip_targets(methods)
        for m,br,why in skipped:
            print("  skip %s @ IL_%04x in %s: %s" % (br["op"],br["off"],m["name"],why))
        if not flips:
            print("  no in-place-flippable failure branch found near outcome logic")
            print("  status: preview only; run --mode patch to write the flips it finds.")
            return False
        for m,br,n_pops,tscore,fscore in flips:
            print("  method %s: flip %s @ IL_%04x -> pop x%d + nop (force win-side fallthrough)"
                  % (m["name"], br["op"], br["off"], n_pops))
            if fscore["wins"]: print("    win side : %s" % ", ".join(repr(x) for x in fscore["wins"][:2]))
            if tscore["loses"]: print("    lose side: %s" % ", ".join(repr(x) for x in tscore["loses"][:2]))
        print("  status: preview only; run --mode patch to apply these flips.")
        return True

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
            if self.method_filter or self.il_dump:
                self._constraint_shapes(selected)
            if self.il_dump:
                self._dump_methods(selected)
        print("  note             : this frontend handles managed IL; native angr remains the frontend for non-IL targets")
        return ok

    def plan_patch(self):
        ok=self.report()
        if not ok:
            return False
        methods=self._matching_methods()
        flipped=self._patch_plan(methods)
        gated=self._gate_taint_plan(methods)
        return flipped or gated

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


    # --- tainted-bool gate analysis (generic gate-expression patch planning) ---
    #
    # This is the "find the shared gate sub-expression, prove it is source-tainted
    # and gate-only, then patch its definition" path. Unlike the branch-flip plan
    # (which neutralises one conditional at a time), this looks for a boolean LOCAL
    # that (a) is tainted by an external source, (b) is bool-typed, and (c) is used
    # ONLY in gatekeeping conditions. Such a local can be forced at its single
    # definition site to open every gate that shares it, without disturbing
    # unrelated code -- and crucially without patching any overloaded helper
    # (e.g. Flip) that the local merely flows THROUGH. The gate-only test is the
    # safety proof that forcing the definition has no effect outside the gates.
    #
    # The search stops at this boolean gate-only node; it does NOT keep walking
    # down the expression tree to the ultimate source (license -> getenv). Taint
    # is only a provenance check ("did this value originate outside"), never the
    # patch target -- the patch target is the boolean part that is gate-only.
    #
    # Scope: intraprocedural, basic-block granular. Taint and bool-typing are
    # approximated from the producing instructions inside each block, and "used
    # only in gatekeeping context" means every block that loads the local ends in
    # a conditional branch. The force constant is resolved by concretely evaluating
    # any flow-through helper (e.g. Flip) on {0,1}; the def-site value region is
    # then overwritten in a length-preserving, stack-balanced way (nop fill +
    # ldc.i4.<const>). An inlined gate (no stored local) is recognised too and
    # routed to branch neutralisation, since it has no definition to force.

    @staticmethod
    def _is_ldloc(op): return op.startswith("ldloc") and not op.startswith("ldloca")
    @staticmethod
    def _is_stloc(op): return op.startswith("stloc")

    def _local_index(self, x):
        op=x["op"]
        if op in ("ldloc.0","ldloc.1","ldloc.2","ldloc.3",
                  "stloc.0","stloc.1","stloc.2","stloc.3"):
            return int(op[-1])
        if op in ("ldloc.s","stloc.s","ldloca.s","ldloc","stloc","ldloca"):
            o=x.get("operand"); return int(o) if isinstance(o,int) else None
        return None

    def _basic_blocks(self, ins):
        """Split a decoded method into basic blocks. Returns (blocks, off_to_idx)
        where blocks is a list of (start_idx, end_idx_exclusive)."""
        off_to_idx={x["off"]:i for i,x in enumerate(ins)}
        leaders={0}
        for i,x in enumerate(ins):
            op=x["op"]
            is_term=(op in ("br.s","br","ret","throw","leave","leave.s")
                     or self._is_cond_branch(op) or op=="switch")
            if not is_term: continue
            if i+1 < len(ins): leaders.add(i+1)
            tgt=x.get("target")
            if isinstance(tgt,int) and tgt in off_to_idx: leaders.add(off_to_idx[tgt])
            elif isinstance(tgt,list):
                for t in tgt:
                    if t in off_to_idx: leaders.add(off_to_idx[t])
        starts=sorted(leaders)
        blocks=[(s, (starts[i+1] if i+1<len(starts) else len(ins)))
                for i,s in enumerate(starts)]
        return blocks, off_to_idx

    def _value_is_bool_producer(self, x):
        """Approximate: does this instruction push a boolean result? Comparison
        opcodes and (in)equality/compare helpers do; loads and arithmetic do not.
        This is what keeps a string/int local from being mistaken for a gate bool."""
        op=x["op"]
        if op in ("ceq","cgt","cgt.un","clt","clt.un"): return True
        if op in ("call","callvirt"):
            t=x.get("text") or ""
            if t.endswith("op_Equality") or t.endswith("op_Inequality"): return True
            if any(c in t for c in self.COMPARE_CALLS): return True
        return False

    def _def_is_bool(self, ins, blk_start, def_idx):
        """A stloc defines a bool if the nearest value-producer before it (within
        the same block) pushes a boolean."""
        j=def_idx-1
        while j>=blk_start and ins[j]["op"]=="nop": j-=1
        return j>=blk_start and self._value_is_bool_producer(ins[j])

    def _source_taint_by_local(self, ins, blocks):
        """Fixpoint over basic blocks: which locals hold a value derived from an
        external SOURCE call. Taint enters at a SOURCE call and flows into the next
        stloc; loading an already-tainted local re-introduces the taint, so a
        compare-of-a-tainted-local stored to a bool local stays tainted.
        Returns {local_index: source_name}."""
        tainted={}
        changed=True
        while changed:
            changed=False
            for (s,e) in blocks:
                cur_src=None
                for j in range(s,e):
                    x=ins[j]; op=x["op"]
                    if op in ("call","callvirt","newobj"):
                        t=x.get("text")
                        if t and any(sc in t for sc in self.SOURCE_CALLS): cur_src=t
                    li=self._local_index(x)
                    if li is None: continue
                    if self._is_ldloc(op) and li in tainted:
                        cur_src=cur_src or tainted[li]
                    elif self._is_stloc(op):
                        if cur_src is not None and li not in tainted:
                            tainted[li]=cur_src; changed=True
                        cur_src=None
        return tainted

    # Per-opcode stack effect, used to find the byte region that computes a value.
    # None means "unknown" (an unknown-arity call): the writer refuses rather than
    # guess, keeping the force byte-safe.
    _CALL_DELTA={"op_Equality":-1,"op_Inequality":-1,"Equals":-1,
                 "GetEnvironmentVariable":0,"ReadAllText":0,"ReadAllBytes":0,
                 "ReadLine":1,"GetValue":-1}

    def _call_stack_delta(self, x):
        t=x.get("text") or ""
        base=t.split("::")[-1].split("(")[0]
        return self._CALL_DELTA.get(base)             # None if unknown -> refuse

    def _stack_delta(self, x):
        op=x["op"]
        if op.startswith(("ldarg","ldloc","ldc.","ldstr","ldnull","ldsfld",
                          "ldloca","ldarga","ldtoken","sizeof")) or op=="dup":
            return 1
        if op in ("nop","break"): return 0
        if op=="pop" or op.startswith("stloc") or op.startswith("starg") or op=="stsfld":
            return -1
        if op=="stfld": return -2
        if op in ("ldfld","ldflda","ldlen","not","neg","isinst","castclass","box",
                  "unbox","unbox.any","ldobj","newarr") or op.startswith("conv."):
            return 0
        if op in ("add","sub","mul","div","div.un","rem","rem.un","and","or","xor",
                  "shl","shr","shr.un","ceq","cgt","cgt.un","clt","clt.un",
                  "ldelem.i4","ldelem.ref","ldelem.u1","ldelem.u2"):
            return -1
        if op in ("call","callvirt","newobj"):
            return self._call_stack_delta(x)
        return None                                   # branches/ret/unknown: not in a value region

    def _value_region(self, ins, blocks, idx_to_block, def_idx):
        """Byte span [start_off, stloc_off) that computes the single value stored by
        ins[def_idx]. Returns None if it cannot be determined byte-safely (an
        unknown-arity call in the way)."""
        bi=idx_to_block.get(def_idx)
        if bi is None: return None
        s,_=blocks[bi]
        depth=0; db={}
        for j in range(s, def_idx+1):
            db[j]=depth
            d=self._stack_delta(ins[j])
            if d is None: return None
            depth+=d
        if db.get(def_idx)!=1: return None            # stloc must consume exactly one
        start=None
        for j in range(def_idx-1, s-1, -1):
            if db.get(j)==0: start=j; break
        if start is None: return None
        return (ins[start]["off"], ins[def_idx]["off"])

    def _resolve_call_method(self, token):
        """Decode the IL of the exact MethodDef a call token refers to (so an
        overloaded helper resolves to the right body). Tests may inject a
        {token: ins} map via self._token_methods."""
        inj=getattr(self, "_token_methods", None)
        if inj and token in inj: return inj[token]
        if not isinstance(token,int) or ((token>>24)&0xff)!=0x06: return None
        if not getattr(self, "pe", None): return None
        try:
            mrow=self.pe.net.mdtables.MethodDef.rows[(token & 0xffffff)-1]
        except Exception:
            return None
        body=_method_body_info(self.pe, mrow)
        if not body or not body.get("code"): return None
        return _decode_cil(body["code"], self.pe)

    _LDC={"ldc.i4.m1":-1,"ldc.i4.0":0,"ldc.i4.1":1,"ldc.i4.2":2,"ldc.i4.3":3,
          "ldc.i4.4":4,"ldc.i4.5":5,"ldc.i4.6":6,"ldc.i4.7":7,"ldc.i4.8":8}

    def _eval_il_const(self, ins, arg, max_steps=400):
        """Concretely evaluate a small single-argument helper method on `arg`.
        Returns the int it returns, or None if it uses an op we do not model. This
        is what lets us resolve the force constant THROUGH a helper like Flip
        without ever patching the helper."""
        if not ins: return None
        off_to_idx={x["off"]:i for i,x in enumerate(ins)}
        st=[]; pc=0; steps=0
        while 0<=pc<len(ins) and steps<max_steps:
            steps+=1; x=ins[pc]; op=x["op"]; npc=pc+1
            if op=="nop": pc=npc; continue
            if op in ("ldarg.0","ldarg.s","ldarg"): st.append(int(arg)); pc=npc; continue
            if op in ("ldarg.1","ldarg.2","ldarg.3"): st.append(0); pc=npc; continue
            if op.startswith("ldc.i4"): st.append(self._LDC.get(op, x.get("operand") or 0)); pc=npc; continue
            if op=="neg": st.append(-st.pop()); pc=npc; continue
            if op=="not": st.append(~st.pop()); pc=npc; continue
            if op=="dup": st.append(st[-1]); pc=npc; continue
            if op=="pop": st.pop(); pc=npc; continue
            if op=="ceq": b=st.pop(); a=st.pop(); st.append(1 if a==b else 0); pc=npc; continue
            if op in ("cgt","cgt.un"): b=st.pop(); a=st.pop(); st.append(1 if a>b else 0); pc=npc; continue
            if op in ("clt","clt.un"): b=st.pop(); a=st.pop(); st.append(1 if a<b else 0); pc=npc; continue
            if op in ("add","sub","mul","and","or","xor"):
                b=st.pop(); a=st.pop()
                st.append({"add":a+b,"sub":a-b,"mul":a*b,"and":a&b,"or":a|b,"xor":a^b}[op]); pc=npc; continue
            if op in ("br.s","br"): pc=off_to_idx.get(x.get("target"),npc); continue
            if op.startswith("brtrue"):
                v=st.pop(); pc=off_to_idx.get(x.get("target"),npc) if v!=0 else npc; continue
            if op.startswith("brfalse"):
                v=st.pop(); pc=off_to_idx.get(x.get("target"),npc) if v==0 else npc; continue
            if op=="ret": return st.pop() if st else 0
            return None                               # unmodelled op -> give up
        return None

    def _gate_helper_chain(self, ins, block, term_idx, li):
        """Helper method bodies the local flows THROUGH between its load and the
        gate branch, in order (each may be None if unresolvable)."""
        s,_=block; load=None
        for j in range(term_idx-1, s-1, -1):
            if self._is_ldloc(ins[j]["op"]) and self._local_index(ins[j])==li: load=j; break
        chain=[]
        if load is None: return chain
        for j in range(load+1, term_idx):
            if ins[j]["op"] in ("call","callvirt"):
                chain.append(self._resolve_call_method(ins[j].get("operand")))
        return chain

    def _resolve_force_constant(self, ins, term_idx, licensed, chain):
        """Pick c in {0,1} for the gate local so control reaches the licensed side,
        composing any flow-through helper. None if it cannot be resolved."""
        op=ins[term_idx]["op"]
        if licensed not in ("fall-through","branch-target"): return None
        if not op.startswith(("brtrue","brfalse")): return None
        for c in (0,1):
            val=c
            for mi in chain:
                val=self._eval_il_const(mi, val) if mi else None
                if val is None: return None           # helper not evaluable
            taken=(val!=0) if op.startswith("brtrue") else (val==0)
            reached="branch-target" if taken else "fall-through"
            if reached==licensed: return c
        return None

    def _gate_taint_candidates(self, m):
        """Source-tainted, bool-typed, gate-only locals, with the def-site value
        region to force, flow-through helpers, licensed side, and force constant."""
        ins=m.get("ins") or []
        if not ins: return []
        blocks, off_to_idx=self._basic_blocks(ins)
        idx_to_block={}
        for bi,(s,e) in enumerate(blocks):
            for j in range(s,e): idx_to_block[j]=bi
        tainted=self._source_taint_by_local(ins, blocks)
        if not tainted: return []
        escaped=set(); def_idx={}; use_idx={}
        for i,x in enumerate(ins):
            op=x["op"]; li=self._local_index(x)
            if li is None: continue
            if op.startswith("ldloca"): escaped.add(li)
            elif self._is_stloc(op): def_idx.setdefault(li,[]).append(i)
            elif self._is_ldloc(op): use_idx.setdefault(li,[]).append(i)
        cands=[]
        for li, src in sorted(tainted.items()):
            if li in escaped: continue                       # address taken; can't reason
            defs=def_idx.get(li,[]); uses=use_idx.get(li,[])
            if not defs or not uses: continue
            # (b) bool-typed: at least one definition is produced by a predicate.
            bdef=None
            for di in defs:
                bi=idx_to_block.get(di)
                if bi is None: continue
                if self._def_is_bool(ins, blocks[bi][0], di): bdef=di; break
            if bdef is None: continue
            # (c) gate-only: every block that LOADS the local ends in a cond branch.
            gate_terms=[]; indirect=[]; gate_only=True
            for ui in uses:
                bi=idx_to_block.get(ui)
                if bi is None: gate_only=False; break
                s,e=blocks[bi]; term_idx=e-1
                if not self._is_cond_branch(ins[term_idx]["op"]):
                    gate_only=False; break
                gate_terms.append(term_idx)
                for j in range(ui+1, term_idx):              # helper between load and branch
                    if ins[j]["op"] in ("call","callvirt") and ins[j].get("text"):
                        indirect.append(ins[j]["text"])
            if not gate_only or not gate_terms: continue
            # licensed side + significance from the first gating branch.
            k=gate_terms[0]; tgt=ins[k].get("target")
            t_idx=off_to_idx.get(tgt) if isinstance(tgt,int) else None
            licensed=None; wins=[]; sig=None
            if t_idx is not None:
                tscore=self._reachable_method_slice_score(m, t_idx)
                fscore=self._reachable_method_slice_score(m, k+1)
                licensed,_=pick_licensed(fscore["score"],"fall-through",tscore["score"],"branch-target")
                use=fscore if licensed=="fall-through" else tscore
                wins=use["wins"]; sig=significance(use["count"], len(ins))
            region=self._value_region(ins, blocks, idx_to_block, bdef)
            chain=self._gate_helper_chain(ins, blocks[idx_to_block[k]], k, li)
            fconst=self._resolve_force_constant(ins, k, licensed, chain)
            cands.append({"kind":"typed-local","method":m,"local":li,"source":src,
                          "def_off":ins[bdef]["off"],"region":region,
                          "branch_offs":[ins[t]["off"] for t in gate_terms],
                          "indirect_via":sorted(set(indirect)),
                          "licensed":licensed,"wins":wins,"significance":sig,
                          "force_const":fconst})
        return cands

    def _inlined_gate_candidates(self, m):
        """Gates whose tainted boolean is computed inline and branched on directly
        (no stored local). There is no definition to force, so the patch target is
        branch neutralisation -- mirroring the native (typeless) path."""
        ins=m.get("ins") or []
        if not ins: return []
        blocks, off_to_idx=self._basic_blocks(ins)
        out=[]
        for (s,e) in blocks:
            term=ins[e-1]
            if not self._is_cond_branch(term["op"]): continue
            src=None; has_bool=False; has_store=False
            for x in ins[s:e]:
                t=x.get("text")
                if x["op"] in ("call","callvirt","newobj") and t and any(sc in t for sc in self.SOURCE_CALLS):
                    src=t
                if self._value_is_bool_producer(x): has_bool=True
                if self._is_stloc(x["op"]): has_store=True
            if not (src and has_bool) or has_store:      # has_store -> typed-local path owns it
                continue
            k=e-1; tgt=term.get("target")
            t_idx=off_to_idx.get(tgt) if isinstance(tgt,int) else None
            licensed=None; wins=[]; sig=None
            if t_idx is not None:
                tscore=self._reachable_method_slice_score(m, t_idx)
                fscore=self._reachable_method_slice_score(m, k+1)
                licensed,_=pick_licensed(fscore["score"],"fall-through",tscore["score"],"branch-target")
                use=fscore if licensed=="fall-through" else tscore
                wins=use["wins"]; sig=significance(use["count"], len(ins))
            npops=self._branch_pop_count(term["op"])
            if licensed=="fall-through" and npops:
                pt=("neutralize %s @ IL_%04x (pop x%d + nop) -> fall through to licensed side"
                    % (term["op"], term["off"], npops))
            else:
                pt="licensed side is the branch target; in-place neutralisation cannot force it"
            out.append({"kind":"inlined","method":m,"source":src,"branch_off":term["off"],
                        "locator":"inline %s @ IL_%04x"%(term["op"],term["off"]),
                        "licensed":licensed,"wins":wins,"significance":sig,"patch_target":pt})
        return out

    def _to_neutral(self, c):
        """Lower an internal candidate dict to the shared GateCandidate."""
        m=c["method"]
        if c["kind"]=="typed-local":
            notes=[]; fv=None
            pt=("force local %d definition at IL_%04x (one site opens every shared gate)"
                % (c["local"], c["def_off"]))
            if c["region"] is None:
                notes.append("def value-region has an unknown-arity call; force write withheld")
            if c["force_const"] is not None:
                fv="local %d := %d" % (c["local"], c["force_const"])
            else:
                notes.append("force constant unresolved (helper not evaluable)")
            return GateCandidate(backend="dotnet", unit=m["name"], kind="typed-local",
                gate_locator="local %d (bool)"%c["local"],
                gate_sites=["IL_%04x"%o for o in c["branch_offs"]],
                tainted=True, source=c["source"], flows_through=c["indirect_via"],
                licensed_side=c["licensed"], win_strings=c["wins"], significance=c["significance"],
                patch_target=pt, force_value=fv, notes=notes)
        return GateCandidate(backend="dotnet", unit=m["name"], kind="inlined",
            gate_locator=c["locator"], gate_sites=["IL_%04x"%c["branch_off"]],
            tainted=True, source=c["source"], flows_through=[],
            licensed_side=c["licensed"], win_strings=c["wins"], significance=c["significance"],
            patch_target=c["patch_target"], force_value=None)

    def _all_gate_candidates(self, methods):
        cands=[]
        for m in methods:
            cands+=self._gate_taint_candidates(m)
            cands+=self._inlined_gate_candidates(m)
        return cands

    def _gate_taint_plan(self, methods):
        """Non-destructive preview of the tainted-gate path, via the shared printer."""
        cands=self._all_gate_candidates(methods)
        return render_plan(".NET IL TAINTED-GATE PLAN (managed; preview, no bytes written)",
                           [self._to_neutral(c) for c in cands])

    def _emit_gate_forces(self, methods, out_arg=None):
        """Write the def-site forces for byte-resolvable typed-local gates. Returns
        (wrote, candidates). Length-preserving: the value region becomes nop padding
        plus a single ldc.i4.<const> right before the stloc."""
        cands=[c for m in methods for c in self._gate_taint_candidates(m)]
        forceable=[c for c in cands
                   if c["region"] is not None and c["force_const"] is not None]
        if not forceable:
            return False, cands
        data=bytearray(_read_file_prefix(self.primary, 1<<30)); applied=0
        for c in forceable:
            code_off=int(c["method"]["body"]["code_off"])
            s_off,e_off=c["region"]; foff=code_off+s_off; length=e_off-s_off
            if length<1 or foff+length>len(data): continue
            for j in range(length): data[foff+j]=0x00            # nop fill
            data[foff+length-1]=0x16 if c["force_const"]==0 else 0x17  # ldc.i4.<const>
            applied+=1
        if not applied:
            return False, cands
        out=out_arg or (self.primary+".patched")
        parent=os.path.dirname(out)
        if parent: os.makedirs(parent, exist_ok=True)
        with open(out,"wb") as f: f.write(data)
        self._last_force_out=out; self._last_force_count=applied
        return True, cands


    # --- branch-flip patching (mirrors native failure-branch neutralisation) ---

    def _is_cond_branch(self, op):
        return any(op.startswith(p) for p in self.COND_BRANCH_PREFIX)

    def _branch_pop_count(self, op):
        """Stack operands a conditional branch consumes (so a neutralising flip
        can pop them and stay stack-balanced)."""
        if op.startswith(("brtrue","brfalse")): return 1
        if op.startswith(("beq","bne.un","bge","bgt","ble","blt")): return 2
        return None

    def _branch_flip_targets(self, methods):
        """Select conditional branches whose TARGET side is the failure side, so
        the branch can be neutralised in place (pop operands + nop) to fall
        through to the win side -- a length-preserving, stack-balanced rewrite.
        Returns (flips, skipped); `skipped` records branches whose win side is the
        target, which cannot be forced in place without relocating code."""
        flips=[]; skipped=[]
        for m in methods:
            body=m.get("body") or {}
            if body.get("more_sects"): continue
            code_size=int(body.get("code_size") or 0)
            calls="\n".join(m["calls"])
            wins0,loses0,_=self._classify_strings(m["strings"])
            if not (wins0 or loses0 or any(x in calls for x in self.COMPARE_CALLS)
                    or any(x in calls for x in self.SOURCE_CALLS)):
                continue
            ins=m["ins"]; off_to_idx={x["off"]:i for i,x in enumerate(ins)}
            for k,br in enumerate(ins):
                op=br["op"]
                if not self._is_cond_branch(op): continue
                tgt=br.get("target")
                if not isinstance(tgt,int): continue
                t_idx=off_to_idx.get(tgt)
                if t_idx is None: continue
                tscore=self._reachable_method_slice_score(m, t_idx)
                fscore=self._reachable_method_slice_score(m, k+1)
                if (fscore["score"]-tscore["score"])>=self.FLIP_MARGIN_MIN and (tscore["loses"] or fscore["wins"]):
                    n_pops=self._branch_pop_count(op)
                    if n_pops is None or br["off"]+br["size"]>code_size or br["size"]<n_pops: continue
                    flips.append((m, br, n_pops, tscore, fscore))
                elif (tscore["score"]-fscore["score"])>=self.FLIP_MARGIN_MIN and (fscore["loses"] or tscore["wins"]):
                    skipped.append((m, br, "win side is the branch target; in-place IL flip cannot grow the body to force it"))
        return flips, skipped

    def _emit_branch_flips(self, flips, skipped, out_arg=None):
        hr(".NET IL BRANCH-FLIP PATCH (force failure branches to the win side)")
        for m,br,why in skipped:
            print("  skip %s @ IL_%04x in %s: %s" % (br["op"], br["off"], m["name"], why))
        if not flips:
            print("  no in-place-flippable failure branch isolated near outcome logic")
            return False
        data=bytearray(_read_file_prefix(self.primary, 1<<30)); applied=0
        for m,br,n_pops,tscore,fscore in flips:
            foff=int(m["body"]["code_off"])+br["off"]; size=br["size"]
            if foff+size>len(data): continue
            for j in range(n_pops): data[foff+j]=0x26          # pop
            for j in range(n_pops,size): data[foff+j]=0x00      # nop
            print("  flip %s @ IL_%04x in %s -> pop x%d + nop (fall through to win side)"
                  % (br["op"], br["off"], m["name"], n_pops))
            if fscore["wins"]: print("       win side : %s" % ", ".join(repr(x) for x in fscore["wins"][:2]))
            if tscore["loses"]: print("       lose side: %s" % ", ".join(repr(x) for x in tscore["loses"][:2]))
            applied+=1
        if not applied:
            print("  no branch patch applied"); return False
        out=out_arg or (self.primary+".patched")
        parent=os.path.dirname(out)
        if parent: os.makedirs(parent, exist_ok=True)
        with open(out,"wb") as f: f.write(data)
        print("  applied %d branch flip(s); wrote %s (original untouched)" % (applied, out))
        return True

    def patch(self, out_arg=None):
        ok=self.report()
        if not ok:
            hr(".NET IL PATCH")
            print("  no IL metadata decoder available; cannot write IL patches")
            return False
        methods=self._matching_methods()
        # Preferred: force a tainted gate local's definition. One byte-safe write
        # opens every gate that shares it, and no overloaded helper is touched.
        hr(".NET IL TAINTED-GATE PATCH (force gate-local definitions)")
        wrote,cands=self._emit_gate_forces(methods, out_arg=out_arg)
        render_plan("selected gate-local forces", [self._to_neutral(c) for c in cands],
                    plan_only=not wrote)
        if wrote:
            print("  applied %d gate-local force(s); wrote %s (original untouched)"
                  % (getattr(self,"_last_force_count",0), getattr(self,"_last_force_out","")))
            return True
        # Fallback: in-place branch neutralisation (inlined gates / non-forceable).
        print("  no byte-forceable tainted gate local; falling back to branch-flip neutralisation")
        flips,skipped=self._branch_flip_targets(methods)
        return self._emit_branch_flips(flips, skipped, out_arg=out_arg)

def select_runtime_frontend(kind, binary, rt, options=None):
    if kind in ("dotnet-apphost","dotnet-managed"):
        return DotNetILFrontend(binary, rt, options=options)
    return None

