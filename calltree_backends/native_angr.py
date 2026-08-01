#!/usr/bin/env python3
"""
Ariadne native angr backend - architecture-agnostic license/gate triage.

Design principle: native targets use one uniform CALL TREE (whole-program call
graph + CFG) in which a function from a .so, a static helper, and an inline check
are all just nodes.  Runtime hosts are routed before solve/patch to a dedicated
frontend (currently .NET IL) because their native CFG is bootstrap/runtime code,
not the application logic.

The target OS is detected from the LOADED OBJECT (PE vs ELF), not from the host.
A useful side effect: angr selects the MS x64 calling convention for a PE main
object, so stack-passed args in the registry SimProcedure resolve for free.

Works unchanged on a standalone crackme and on a dynamically-linked, gated app.

Sources recovered: stdin (always), files, environment variables, and -- on
Windows targets -- registry value/subkey names.

Modes: advise | solve | patch | runtime-report

Boundaries worth stating plainly:
  * PATCH and the dominance gate finder are fully OS-agnostic; registry is a
    *source*, and patching does not care about sources, so they need nothing
    OS-specific.
  * verify_real is a HOST capability, not a target property. It runs ./binary
    via subprocess, so it only verifies on a Linux host running a Linux target.
    For a PE target, solve drops to symbolic-only and labels candidates as
    unverified (the host cannot execute the PE, and there is no channel here to
    materialize a registry write). Verified PE solving is a separate,
    host-dependent build-out (Wine + `reg add`).
  * Runtime hosts (.NET apphost, Electron, PyInstaller, Unity, JVM launchers)
    are detected before solve/patch. Their native CFG is bootstrap/runtime code,
    so native solve/patch is refused by default and the tool reports likely
    payload artifacts for a runtime-specific frontend.
"""
import sys, logging, time
import os, shutil, subprocess
# Current angr spills its CFG-node and function tables to an on-disk LMDB store to
# bound RAM on huge targets. For crackme/challenge-sized binaries that trade is
# backwards: every `cfg.functions.values()` / node lookup then pays repeated
# serialize+deserialize round-trips (tens of seconds of pure I/O on a statically
# linked target, and it made source recovery re-deserialize the whole table once
# per API). Default to the in-memory tables -- markedly faster with identical CFG
# results on challenge-sized inputs -- while leaving an explicit override for the
# rare multi-hundred-MB target where disk spilling is what keeps angr from OOMing.
os.environ.setdefault("USE_SPILLING_CFGNODE_DICT", "False")
os.environ.setdefault("USE_SPILLING_FUNCTION_DICT", "False")
for n in ("angr","cle","pyvex","claripy","archinfo"):
    logging.getLogger(n).setLevel(logging.ERROR)
# Missing unicorn bindings are a common, non-fatal speed-path issue in sandboxed
# environments; keep that specific logger quiet so solve/patch output stays about
# the analysis result rather than an optional accelerator.
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
import angr, claripy, networkx as nx
# Allow importing the backend package when this module is loaded directly rather
# than through main.py (which already puts the workspace root on sys.path).
for _p in (os.getcwd(), os.path.dirname(os.path.dirname(os.path.abspath(__file__)))):
    if os.path.isdir(os.path.join(_p, "calltree_backends")) and _p not in sys.path:
        sys.path.insert(0, _p)

from calltree_backends.frontend import AnalyzerFrontend, AnalyzerOptions
from calltree_backends.util import hr, read_file_prefix as _read_file_prefix, glob_limited as _glob_limited
from calltree_backends.gates import GateCandidate, render_plan

def verify_real(binary, stdin_bytes, files, envs):
    """Drive recovered inputs into the REAL binary; True iff it prints success.
    Linux-host only. Runs the target from its own directory so relative file
    reads and sibling-library lookups behave like a normal launch, and supports
    both relative and absolute target paths."""
    binpath=os.path.abspath(binary)
    run_cwd=os.path.dirname(binpath) or os.getcwd()
    env=os.environ.copy()
    existing_ld=env.get("LD_LIBRARY_PATH")
    env["LD_LIBRARY_PATH"]=run_cwd+os.pathsep+existing_ld if existing_ld else run_cwd
    for k,v in envs.items(): env[k]=v
    written=[]
    try:
        for path,content in files.items():
            real_path=path if os.path.isabs(path) else os.path.join(run_cwd, path)
            try:
                parent=os.path.dirname(real_path)
                if parent: os.makedirs(parent, exist_ok=True)
                with open(real_path,"wb") as f: f.write(content)
                written.append(real_path)
            except Exception:
                pass
        r=subprocess.run([binpath], input=stdin_bytes,
                         capture_output=True, timeout=6, env=env, cwd=run_cwd)
        out=r.stdout.lower()
        return (b"unlicensed" not in out) and len(out.strip())>0 and any(w in out for w in [b"toolkit",b"sum=",b"bucket",b"correct",b"notes",b"granted",b"welcome",
                                      b"thank you",b"licensed",b"unlocked"])
    except Exception:
        return False
    finally:
        for p in written:
            try: os.remove(p)
            except Exception: pass

SYS=("libc.","libstdc++.","libm.","libgcc_s.","ld-linux","libpthread.","libdl.",
     "librt.","libutil.","libresolv.","ld64.")
# Windows + CoreCLR/.NET runtime modules. These are platform/runtime code, NOT
# the target program, so they must not be counted as "ours" nor force-loaded.
WIN_SYS=("kernel32","kernelbase","ntdll","advapi32","user32","gdi32","ole32",
         "oleaut32","shell32","shlwapi","ws2_32","rpcrt4","sechost","combase",
         "msvcrt","ucrtbase","vcruntime","msvcp","api-ms-win","bcrypt","crypt32",
         "wininet","winhttp","comctl32","comdlg32","setupapi","version.dll",
         "psapi","dbghelp","secur32","iphlpapi","mswsock","winmm","powrprof",
         "hostfxr","hostpolicy","coreclr","clrjit","clrcompression","nethost",
         "mscordaccore","mscordbi","system.native","ole32","gdiplus")

def is_system_module(name):
    """True for platform/runtime modules (libc family, Windows DLLs, CoreCLR
    host). Used both when deciding what to force-load and when counting 'our'
    code, so the two stay consistent across OSes."""
    n=(name or "").lower().replace("\\","/")
    if "/windows/system32/" in n or "/syswow64/" in n: return True
    b=n.rsplit("/",1)[-1]
    return any(s in b for s in SYS) or any(s in b for s in WIN_SYS)

def node_insns(proj, node):
    """Capstone instructions for a CFG node's block.

    Passing the CFG node's known `size` is the whole point: without it,
    `proj.factory.block(addr)` lifts the block to VEX just to discover its
    boundary before capstone ever runs. The CFG already recovered that boundary,
    so handing capstone the size skips the VEX lift entirely (~10x faster when
    scanning every branch node of a large call tree). Returns [] on any failure."""
    try:
        size=getattr(node, "size", None)
        blk=proj.factory.block(node.addr, size=size) if size else proj.factory.block(node.addr)
        return blk.capstone.insns
    except Exception:
        return []

def obj_of(proj, addr):
    """(module_basename, is_main_object) for a rebased address."""
    o=proj.loader.find_object_containing(addr)
    if o is None: return ("?", False)
    if o is getattr(proj.loader,"extern_object",None): return ("extern", False)
    b=(getattr(o,"binary","") or "?").rsplit("/",1)[-1]
    return (b, o is proj.loader.main_object)

from calltree_backends.outcomes import WIN_WORDS, LOSE_WORDS

# ---------------------------------------------------------------------------
# OS-keyed source table. This is the ONLY place the pipeline branches on OS.
# `reg` = the register holding the *named string* argument, per the target's
# calling convention. W-suffixed APIs take UTF-16 (wide); others are byte/ANSI.
# ---------------------------------------------------------------------------
SOURCE_TABLE = {
  "linux": {                                   # SysV x64: arg1=rdi arg2=rsi arg3=rdx
    "file":     {"fopen":"rdi","fopen64":"rdi","open":"rdi","open64":"rdi","openat":"rsi"},
    "env":      {"getenv":"rdi","secure_getenv":"rdi"},
    "registry": {},
  },
  "windows": {                                 # MS x64: arg1=rcx arg2=rdx arg3=r8 arg4=r9
    "file":     {"CreateFileA":"rcx","CreateFileW":"rcx","fopen":"rcx","_wfopen":"rcx"},
    "env":      {"getenv":"rcx","GetEnvironmentVariableA":"rcx","GetEnvironmentVariableW":"rcx"},
    "registry": {"RegOpenKeyExA":"rdx","RegOpenKeyExW":"rdx",       # subkey path
                 "RegQueryValueExA":"rdx","RegQueryValueExW":"rdx",  # value name
                 "RegGetValueA":"rdx","RegGetValueW":"rdx"},
  },
}
def _is_wide(api): return api.endswith("W")

def target_os(proj):
    """Detect OS from the loaded object, not the host."""
    mo = proj.loader.main_object
    cls = type(mo).__name__.lower()            # 'pe' | 'elf' | 'macho'
    if "pe" in cls: return "windows"
    if "mach" in cls: return "macos"
    if "win" in (getattr(mo, "os", "") or "").lower(): return "windows"
    return "linux"

def base(s): return s.split("@")[0]

# ---------------------------------------------------------------------------
# 1. LOADER: always produce a uniform call tree (libraries become nodes).
# ---------------------------------------------------------------------------
def load_calltree(binary):
    a0=angr.Project(binary, auto_load_libs=False)
    deps=[d for d in a0.loader.main_object.deps if not is_system_module(d)]
    force=[]
    for d in deps:
        for cand in ("./"+d, d):
            try:
                open(cand,"rb"); force.append(cand); break
            except Exception: pass
    proj=angr.Project(binary, auto_load_libs=False, force_load_libs=force)
    cfg=proj.analyses.CFGFast(normalize=True)
    return proj, cfg

def read_cstr(proj, addr, n=160):
    try: raw=proj.loader.memory.load(addr,n)
    except Exception: return None
    e=raw.find(b"\x00"); return raw[:e if e!=-1 else n]

def read_wstr(proj, addr, n=320):
    """UTF-16LE string until a double-null; returned as latin1 bytes so callers
    can decode uniformly with read_cstr output."""
    try: raw=proj.loader.memory.load(addr,n)
    except Exception: return None
    out=bytearray()
    for i in range(0, len(raw)-1, 2):
        if raw[i]==0 and raw[i+1]==0: break
        out+=raw[i:i+2]
    try: return out.decode("utf-16-le").encode("latin1","replace")
    except Exception: return bytes(out)

def str_vaddrs(proj, needle):
    out=[]
    for o in proj.loader.all_objects:
        for seg in getattr(o,"segments",[]):
            try: data=proj.loader.memory.load(seg.vaddr,seg.memsize)
            except Exception: continue
            i=data.find(needle)
            while i!=-1: out.append(seg.vaddr+i); i=data.find(needle,i+1)
    return out

def rip_ref_index(proj, cfg):
    """Map rip-relative constant addresses to call-tree blocks that reference
    them. Building this once avoids rescanning every block for every candidate
    outcome string on large challenge binaries."""
    import re
    refs={}
    pat=re.compile(r"rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b")
    for f in cfg.functions.values():
        try: blocks=list(f.blocks)
        except Exception: continue
        for blk in blocks:
            for ins in blk.capstone.insns:
                m=pat.search(ins.op_str)
                if not m: continue
                try:
                    disp=int(m.group(2),16)
                    if m.group(1)=="-": disp=-disp
                    tgt=ins.address+ins.size+disp
                    refs.setdefault(tgt,set()).add(blk.addr)
                except Exception: pass
    return refs

def block_refs(proj, cfg, vaddr):
    """call-tree blocks that load this address (rip-relative)."""
    return rip_ref_index(proj,cfg).get(vaddr,set())

# ---------------------------------------------------------------------------
# 2. SINKS: classify outcome nodes by the strings they emit (no architecture).
# ---------------------------------------------------------------------------
def outcome_sinks(proj, cfg):
    win=set(); lose=set(); seen=[]
    refs=rip_ref_index(proj,cfg)
    for o in proj.loader.all_objects:
        for seg in getattr(o,"segments",[]):
            try: data=proj.loader.memory.load(seg.vaddr,seg.memsize)
            except Exception: continue
            i=0
            while i<len(data):
                j=data.find(b"\x00",i)
                if j==-1: break
                s=data[i:j]
                # Accept common whitespace (tab/newline/CR) inside the string, not
                # just the printable-ASCII range. Almost every printf/puts outcome
                # string ends in "\n" (and some start with one, e.g. "\n[+] Access
                # granted.\n"); requiring strictly 0x20..0x7e silently discarded the
                # majority of real win/lose anchors, leaving string-based sink
                # detection blind on most crackmes.
                if 3<=len(s)<=64 and all(c in (9,10,13) or 32<=c<127 for c in s):
                    low=s.decode().lower()
                    cat=None
                    if any(w in low for w in LOSE_WORDS): cat="lose"
                    elif any(w in low for w in WIN_WORDS): cat="win"
                    if cat:
                        for b in refs.get(seg.vaddr+i,()):
                            (win if cat=="win" else lose).add(b)
                            seen.append((cat,s.decode(),hex(b)))
                i=j+1
    return win, lose, seen

# ---------------------------------------------------------------------------
# 3. SOURCES: input nodes (uniform; stdin always assumed). Table-driven per OS.
# ---------------------------------------------------------------------------
def functions_by_name(cfg):
    """One pass over the function manager, grouping functions by name.

    In current angr the function table is LMDB-backed, so every
    ``cfg.functions.values()`` deserializes all functions from disk. Recovering
    sources touches one API name at a time, so scanning ``values()`` per API
    re-deserialized the whole table N times (tens of seconds on a statically
    linked binary with thousands of functions). Building the index once and
    looking API names up in it collapses that to a single pass."""
    idx={}
    for f in cfg.functions.values():
        idx.setdefault(f.name, []).append(f)
    return idx

def recover_named(proj, cfg, by_name, api, reg):
    """Recover the string passed in `reg` at each call site of `api`.

    `by_name` is the index from :func:`functions_by_name` (name -> [functions]).

    Handles the direct `lea <argreg>, [rip+...]` shape and the very common
    one-hop register copy produced by compilers, e.g. `lea rax, [...] ; mov rdi,
    rax ; call getenv`. Uniform across loaders: an ELF PLT entry lives in the
    main object, while a PE import is modelled as BOTH an in-range IAT thunk
    (whose predecessor is just padding) and an out-of-range SimProcedure stub
    (whose predecessor is the real caller). We therefore union predecessors over
    EVERY cfg function named `api` rather than picking one stub by address range."""
    import re
    out=[]; wide=_is_wide(api); seen=set()
    nodes=[cfg.model.get_any_node(f.addr) for f in by_name.get(api, [])]
    rip_pat=re.compile(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\]")

    def _split_ops(op_str):
        parts=[p.strip() for p in (op_str or "").split(",", 1)]
        return (parts[0], parts[1]) if len(parts)==2 else (parts[0] if parts else "", "")

    # Compilers frequently stage pointer args through the 32-bit sub-register
    # (e.g. `mov edi, eax` for an integer arg), so normalise to the 64-bit name
    # before comparing/tracking registers.
    _REG64={
        "edi":"rdi","esi":"rsi","edx":"rdx","ecx":"rcx","eax":"rax","ebx":"rbx",
        "ebp":"rbp","esp":"rsp",
        "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12",
        "r13d":"r13","r14d":"r14","r15d":"r15",
    }
    def _norm(r): return _REG64.get(r, r)

    def _read_rip_string(ins):
        m=rip_pat.search(ins.op_str or "")
        if not m: return None
        try:
            val=m.group(2)
            disp=int(val,16) if (val.startswith("0x") or any(c in val.lower() for c in "abcdef")) else int(val,10)
            if m.group(1)=="-": disp=-disp
            tgt=ins.address+ins.size+disp
            s=read_wstr(proj,tgt) if wide else read_cstr(proj,tgt)
            return s.decode("latin1") if s else None
        except Exception:
            return None

    for node in nodes:
        if node is None: continue
        for pred in cfg.model.get_predecessors(node):
            if pred.addr in seen: continue
            seen.add(pred.addr)
            try:
                insns=list(pred.block.capstone.insns)
            except Exception:
                continue
            wanted={_norm(reg)}
            for ins in reversed(insns):
                dst,src=_split_ops(ins.op_str)
                dst_n,src_n=_norm(dst),_norm(src)
                if dst_n not in wanted:
                    continue
                if ins.mnemonic=="lea":
                    s=_read_rip_string(ins)
                    if s: out.append(s)
                    break
                # Track plain and width-extending register copies (mov/movsxd/
                # movzx/movsx) from another register; a memory load (src has
                # "[") clobbers with a non-static value, so it falls through.
                if ins.mnemonic.startswith("mov") and src and "[" not in src:
                    wanted.discard(dst_n)
                    wanted.add(src_n)
                elif ins.mnemonic not in ("cmp","test","push"):
                    # The tracked register is written by an instruction we can't
                    # resolve to a static pointer (xor/add/pop/mem-load/...), so
                    # stop tracking it rather than walk back to an unrelated lea.
                    # cmp/test/push only read their first operand, so they don't
                    # clobber it.
                    wanted.discard(dst_n)
    return out

def detect_sources(proj, cfg):
    os_=target_os(proj)
    tbl=SOURCE_TABLE.get(os_, SOURCE_TABLE["linux"])
    by_name=functions_by_name(cfg)      # single deserialization of the LMDB table
    files=[]; envs=[]; regs=[]
    for api,reg in tbl["file"].items():     files+=recover_named(proj,cfg,by_name,api,reg)
    for api,reg in tbl["env"].items():      envs +=recover_named(proj,cfg,by_name,api,reg)
    for api,reg in tbl["registry"].items(): regs +=recover_named(proj,cfg,by_name,api,reg)
    return os_, sorted(set(files)), sorted(set(envs)), sorted(set(regs))

# ---------------------------------------------------------------------------
# 3b. RUNTIME HOSTS: native launchers whose real program lives elsewhere.
# ---------------------------------------------------------------------------
def _existing(paths):
    out=[]; seen=set()
    for x in paths:
        if not x or x in seen: continue
        seen.add(x)
        try:
            if os.path.exists(x): out.append(x)
        except Exception: pass
    return out

def detect_runtime(proj, cfg, binary, os_, files, envs, regs):
    """Detect native runtime hosts before treating their CFG as application
    code.  A .NET apphost, Electron launcher, PyInstaller stub, etc. can have a
    perfectly valid native CFG, but its branches are bootstrap/runtime noise; the
    real app logic needs a runtime-specific frontend."""
    binpath=getattr(proj.loader.main_object,"binary","") or binary
    data=_read_file_prefix(binpath)
    low=data.lower()
    d=os.path.dirname(os.path.abspath(binpath)) or "."
    base_no_ext=os.path.splitext(os.path.basename(binpath))[0]
    abs_base=os.path.join(d, base_no_ext)

    def has(*needles): return [n for n in needles if n in low]
    candidates=[]

    # .NET native apphost / CoreCLR bootstrapper or managed PE.
    ev=[]; payloads=[]; score=0
    dotnet_envs=[e for e in envs if e.upper().startswith(("COREHOST_","DOTNET_","_DOTNET_"))]
    if dotnet_envs:
        score+=45; ev.append("environment probes are CoreHost/.NET-only: "+", ".join(dotnet_envs[:6])+(" ..." if len(dotnet_envs)>6 else ""))
    m=has(b"corehost_trace", b"dotnet_runtime_id", b"hostfxr", b"hostpolicy", b"coreclr", b"clrjit",
          b".runtimeconfig.json", b".deps.json", b"dotnet_bundle", b"apphost", b"nethost")
    if m:
        score+=min(45, 8*len(m)); ev.append("native image contains .NET host markers: "+", ".join(x.decode("latin1","replace") for x in m[:8]))
    if b"bsjb" in low or b"mscoree.dll" in low or b"_corexemain" in low:
        score+=40; ev.append("PE contains CLR/CLI metadata/import markers")
    payloads += _existing([abs_base+".runtimeconfig.json", abs_base+".deps.json", abs_base+".dll"])
    payloads += _glob_limited(os.path.join(d,"*.runtimeconfig.json"), 8)
    payloads += _glob_limited(os.path.join(d,"*.deps.json"), 8)
    payloads += _glob_limited(os.path.join(d,"*.dll"), 12)
    if any(x.endswith((".runtimeconfig.json",".deps.json")) for x in payloads):
        score+=25; ev.append("adjacent .runtimeconfig/.deps files found")
    if score:
        kind="dotnet-managed" if (b"bsjb" in low and not dotnet_envs) else "dotnet-apphost"
        candidates.append((score,kind,ev,payloads))

    # JVM launchers/native-image wrappers.
    ev=[]; payloads=[]; score=0
    m=has(b"jni_createjavavm", b"jvm.dll", b"libjvm", b"java_home", b".jar", b"jli_launch")
    if m:
        score+=min(80, 15*len(m)); ev.append("JVM launcher markers: "+", ".join(x.decode("latin1","replace") for x in m[:8]))
    payloads += _glob_limited(os.path.join(d,"*.jar"), 16)
    if payloads:
        score+=20; ev.append("adjacent .jar payload(s) found")
    if score: candidates.append((score,"java-launcher",ev,payloads))

    # Electron / Node desktop apps.
    ev=[]; payloads=[]; score=0
    m=has(b"electron", b"node.dll", b"chrome_elf.dll", b"v8_context_snapshot", b"app.asar", b"node_modules")
    if m:
        score+=min(80, 12*len(m)); ev.append("Electron/Node markers: "+", ".join(x.decode("latin1","replace") for x in m[:8]))
    payloads += _existing([os.path.join(d,"resources","app.asar"), os.path.join(d,"resources","app")])
    payloads += _glob_limited(os.path.join(d,"resources","*.asar"), 8)
    if payloads:
        score+=30; ev.append("Electron resources/app payload found")
    if score: candidates.append((score,"electron-node",ev,payloads))

    # PyInstaller-style Python bootloaders.
    ev=[]; payloads=[]; score=0
    m=has(b"pyinstaller", b"pyiboot", b"_mei", b"_meipass", b"pyz-00.pyz", b"pyi-")
    if m:
        score+=min(90, 18*len(m)); ev.append("PyInstaller/Python bootloader markers: "+", ".join(x.decode("latin1","replace") for x in m[:8]))
    if score: candidates.append((score,"pyinstaller",ev,payloads))

    # Unity / Mono / IL2CPP launchers.
    ev=[]; payloads=[]; score=0
    m=has(b"unityplayer.dll", b"gameassembly.dll", b"global-metadata.dat", b"mono-2.0", b"assembly-csharp.dll")
    if m:
        score+=min(90, 18*len(m)); ev.append("Unity/Mono/IL2CPP markers: "+", ".join(x.decode("latin1","replace") for x in m[:8]))
    payloads += _existing([os.path.join(d,"UnityPlayer.dll"), os.path.join(d,"GameAssembly.dll")])
    payloads += _glob_limited(os.path.join(d,"*_Data","Managed","Assembly-CSharp.dll"), 8)
    payloads += _glob_limited(os.path.join(d,"*_Data","il2cpp_data","Metadata","global-metadata.dat"), 8)
    if payloads:
        score+=25; ev.append("Unity managed/IL2CPP payload artifacts found")
    if score: candidates.append((score,"unity-mono-il2cpp",ev,payloads))

    if not candidates:
        return {"kind":"native","confidence":0,"evidence":[],"payloads":[],"note":"no runtime-host markers detected"}
    score,kind,ev,payloads=max(candidates, key=lambda x:x[0])
    # Keep confidence bounded and stable rather than pretending exactness.
    conf=max(1,min(100,score))
    uniq=[]; seen=set()
    for x in payloads:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return {"kind":kind,"confidence":conf,"evidence":ev,"payloads":uniq,
            "note":"native CFG is likely bootstrap/runtime code, not the full application"}

def runtime_frontend_hint(kind):
    if kind.startswith("dotnet"):
        return ("Use a .NET/IL frontend: parse CLI metadata, build an IL-level CFG, "
                "model Console/Environment/File/Registry APIs, and solve at IL level. ")
    if kind=="java-launcher":
        return ("Use a JVM bytecode frontend: analyze .class/.jar methods and model Java APIs; "
                "native launcher branches are usually JVM bootstrap noise.")
    if kind=="electron-node":
        return ("Use an Electron/Node frontend: inspect resources/app.asar or JS bundles; "
                "native PE branches mostly belong to Chromium/Node startup.")
    if kind=="pyinstaller":
        return ("Use a PyInstaller/Python frontend: extract the PYZ/archive and analyze Python bytecode/source; "
                "the bootloader CFG is not the app CFG.")
    if kind=="unity-mono-il2cpp":
        return ("Use a Unity frontend: inspect Assembly-CSharp.dll for Mono builds or metadata+GameAssembly "
                "for IL2CPP builds; launcher branches are engine/runtime noise.")
    return "Use a runtime-specific frontend; native dominance gates are likely runtime noise."

def print_runtime_report(rt):
    hr("RUNTIME DETECTION (native host vs real application payload)")
    if not rt or rt.get("kind")=="native":
        print("  runtime      : native / unknown")
        print("  note         : %s" % ((rt or {}).get("note") or "no runtime-host markers detected"))
        return
    print("  runtime      : %s  (confidence %d/100)" % (rt["kind"], rt.get("confidence",0)))
    print("  note         : %s" % rt.get("note",""))
    if rt.get("evidence"):
        print("  evidence:")
        for e in rt["evidence"][:8]: print("    - "+e)
    if rt.get("payloads"):
        print("  likely payload/artifact files:")
        for p in rt["payloads"][:20]: print("    - "+p)
        if len(rt["payloads"])>20:
            print("    ... %d more" % (len(rt["payloads"])-20))
    print("  guidance     : %s" % runtime_frontend_hint(rt["kind"]))
    print("  policy       : native solve/patch is disabled by default for runtime hosts;"
          " use --force-native-runtime only for authorized low-level runtime research")

# ---------------------------------------------------------------------------
# 4. SOLVE: symbolic sources, explore the call tree to a win sink.
# ---------------------------------------------------------------------------
def make_symenv(state, names, L=32):
    syms={}
    for nm in names:
        buf=claripy.BVS("env_"+nm, L*8); addr=state.heap.allocate(L+1)
        state.memory.store(addr,buf); state.memory.store(addr+L,claripy.BVV(0,8))
        for i in range(L):
            b=buf.get_byte(i); state.solver.add(claripy.Or(b==0,claripy.And(b>=0x20,b<=0x7e)))
        syms[nm]={"addr":addr,"bv":buf}
    return syms

def make_symreg(state, names, L=32):
    """Registry symbols are written into the CALLER's output buffer by the
    SimProcedure, so (unlike env) they need no pre-allocated address here."""
    syms={}
    for nm in names:
        bv=claripy.BVS("reg_"+nm, L*8)
        for i in range(L):
            b=bv.get_byte(i); state.solver.add(claripy.Or(b==0,claripy.And(b>=0x20,b<=0x7e)))
        syms[nm]={"bv":bv}
    return syms

def solve(proj, cfg, win, lose, files, envs, regs, binary, os_="linux",
          maxlen=24, budget=120):
    hr("SOLVE (uniform: symbolic sources -> reach a win node)")
    if not win:
        print("  no win sink identified; cannot define success"); return
    L=32; t0=time.time()
    fs={}; fsyms={}
    for p in files:
        c=claripy.BVS("file_"+p, L*8); fs[p]=angr.SimFile(p,content=c,size=L); fsyms[p]=c
    for N in range(1, maxlen+1):
        if time.time()-t0>budget:
            print("  budget exceeded (path explosion) at %.1fs" % (time.time()-t0)); return
        flag=claripy.BVS("stdin",N*8)
        st=proj.factory.full_init_state(
            fs=fs, stdin=angr.SimFileStream(name="stdin",content=flag,has_end=True),
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        for i in range(N):
            b=flag.get_byte(i)
            st.solver.add(b>=0x01, b<=0xff)  # any non-null byte (printable or not)
        for p,c in fsyms.items():
            for i in range(L):
                b=c.get_byte(i); st.solver.add(claripy.Or(b==0x0a,claripy.And(b>=0x20,b<=0x7e)))
        esyms=make_symenv(st, envs, L)
        if envs:
            for api,proc in (
                ("getenv", _symgetenv(esyms)()),
                ("secure_getenv", _symgetenv(esyms)()),
                ("GetEnvironmentVariableA", _sym_getenv_win(esyms, wide=False, L=L)()),
                ("GetEnvironmentVariableW", _sym_getenv_win(esyms, wide=True,  L=L)()),
            ):
                _hook_symbol_if_present(proj, api, proc)
        rsyms=make_symreg(st, regs, L)
        if regs:
            for api in ("RegQueryValueExA","RegQueryValueExW"):
                _hook_symbol_if_present(proj, api, _symreg(rsyms)())
        sm=proj.factory.simgr(st)
        sm.use_technique(angr.exploration_techniques.Explorer(find=win,avoid=lose))
        steps=0
        while sm.active and steps<500:
            sm.step(); steps+=1
            if len(sm.found)>=3 or len(sm.active)>1500 or time.time()-t0>budget: break
        for s in sm.found:
            stdin_b=s.solver.eval(flag, cast_to=bytes)
            file_vals={p:s.solver.eval(c,cast_to=bytes) for p,c in fsyms.items()}
            env_vals={nm:s.solver.eval(d["bv"],cast_to=bytes).split(b'\x00')[0].decode("latin1","replace")
                      for nm,d in esyms.items()}
            reg_vals={nm:s.solver.eval(d["bv"],cast_to=bytes).split(b'\x00')[0]
                      for nm,d in rsyms.items()}
            if os_=="linux":
                if verify_real(binary, stdin_b, file_vals, env_vals):
                    print("  VERIFIED unlock (%.1fs):" % (time.time()-t0))
                    print("    STDIN : %r" % stdin_b)
                    for p,v in file_vals.items(): print("    FILE %r: %r" % (p, v.split(b'\n')[0]))
                    for nm,v in env_vals.items(): print("    ENV  %r: %r" % (nm, v))
                    for nm,v in reg_vals.items(): print("    REG  %r: %r" % (nm, v))
                    return
            else:
                # Host cannot execute a non-Linux target; report symbolic
                # candidate honestly rather than claim verification.
                print("  SYMBOLIC candidate (%.1fs; host cannot execute %s target -- unverified):"
                      % (time.time()-t0, os_))
                print("    STDIN : %r" % stdin_b)
                for p,v in file_vals.items(): print("    FILE %r: %r" % (p, v.split(b'\n')[0]))
                for nm,v in env_vals.items(): print("    ENV  %r: %r" % (nm, v.decode("latin1","replace") if isinstance(v,bytes) else v))
                for nm,v in reg_vals.items(): print("    REG  %r: %r" % (nm, v))
                return
    if os_=="linux":
        print("  reached win nodes but none verified, or no solution in budget")
        print("  (the general 'reach a win node' oracle can hit spurious paths;")
        print("   verification rejects them -- a known cost of architecture-agnosticism)")
    else:
        print("  no symbolic solution in budget")

def _hook_symbol_if_present(proj, name, proc):
    """Hook an imported/API symbol only when the loader actually found it.
    angr logs a noisy ERROR for hook_symbol('missing_name'), which is expected
    on PE/.NET apphosts that use GetEnvironmentVariable* but not getenv."""
    try:
        if proj.loader.find_symbol(name) is None: return False
        proj.hook_symbol(name, proc, replace=True)
        return True
    except Exception:
        return False

def _state_cstr(state, ptr, n=160):
    try:
        addr=state.solver.eval(ptr)
        out=bytearray()
        for i in range(n):
            b=state.solver.eval(state.memory.load(addr+i,1))
            if b==0: break
            out.append(b)
        return out.decode("latin1","replace")
    except Exception:
        return None

def _state_wstr(state, ptr, n=160):
    try:
        addr=state.solver.eval(ptr)
        out=bytearray()
        for i in range(n):
            lo=state.solver.eval(state.memory.load(addr+2*i,1))
            hi=state.solver.eval(state.memory.load(addr+2*i+1,1))
            if lo==0 and hi==0: break
            out += bytes((lo,hi))
        return out.decode("utf-16-le","replace")
    except Exception:
        return None

def _symgetenv(esyms):
    class G(angr.SimProcedure):
        def run(self, name_ptr):
            nm=_state_cstr(self.state, name_ptr)
            return esyms[nm]["addr"] if nm in esyms else 0
    return G

def _sym_getenv_win(esyms, wide=False, L=32):
    """GetEnvironmentVariable{A,W}(name, outbuf, size).  Return 0 for unknown
    names.  For known names, write a symbolic value into the caller buffer and
    return a plausible copied length.  This models the environment source well
    enough for path exploration without requiring a real Windows environment."""
    class GE(angr.SimProcedure):
        def run(self, name_ptr, outbuf, size):
            nm=_state_wstr(self.state, name_ptr) if wide else _state_cstr(self.state, name_ptr)
            if nm not in esyms: return 0
            bv=esyms[nm]["bv"]
            if not self.state.solver.is_true(outbuf==0) and not self.state.solver.is_true(size==0):
                if wide:
                    for i in range(L):
                        self.state.memory.store(outbuf+2*i, bv.get_byte(i))
                        self.state.memory.store(outbuf+2*i+1, claripy.BVV(0,8))
                    self.state.memory.store(outbuf+2*L, claripy.BVV(0,16),
                                            endness=self.state.arch.memory_endness)
                else:
                    self.state.memory.store(outbuf, bv)
                    self.state.memory.store(outbuf+L, claripy.BVV(0,8))
            return L
    return GE

def _symreg(rsyms, L=32):
    """RegQueryValueEx{A,W}(hKey, lpValueName, lpReserved, lpType, lpData,
    lpcbData). Writes a symbolic buffer into the caller's lpData and reports its
    size in lpcbData; returns ERROR_SUCCESS for known value names, else
    ERROR_FILE_NOT_FOUND so gates that branch on the return code behave. angr
    maps the (partly stack-passed) args via the PE's MS x64 calling convention."""
    class RegQ(angr.SimProcedure):
        def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
            try: nm=self.state.mem[lpValueName].string.concrete
            except Exception: return 0
            if isinstance(nm,bytes): nm=nm.decode("latin1","replace")
            if nm not in rsyms: return 2          # ERROR_FILE_NOT_FOUND
            if not self.state.solver.is_true(lpData==0):
                self.state.memory.store(lpData, rsyms[nm]["bv"])
            if not self.state.solver.is_true(lpcbData==0):
                self.state.memory.store(lpcbData, claripy.BVV(L,32),
                                        endness=self.state.arch.memory_endness)
            return 0                              # ERROR_SUCCESS
    return RegQ

# ---------------------------------------------------------------------------
# 5. PATCH: find the deciding branch on the call tree and flip it toward win.
# ---------------------------------------------------------------------------
def reaches(cfg_graph, start_node, targets):
    seen=set(); stack=[start_node]
    while stack:
        n=stack.pop()
        if n in seen: continue
        seen.add(n)
        if n.addr in targets: return True
        stack.extend(cfg_graph.successors(n))
    return False

def reverse_reachers(cfg_graph, targets):
    """All CFG nodes that can reach any target address, computed once by a
    reverse traversal. Equivalent to repeated reaches(...), but fast enough for
    large FLARE/CGC-style binaries."""
    roots=[n for n in cfg_graph.nodes() if n.addr in targets]
    seen=set(roots); stack=list(roots)
    while stack:
        n=stack.pop()
        for p in cfg_graph.predecessors(n):
            if p not in seen:
                seen.add(p); stack.append(p)
    return seen

def find_decisions(proj, cfg, win, lose):
    """All conditional branches where one successor can reach a failure sink
    but not a win sink. Neutralizing every one of them forces success even for
    multi-branch inline checks (e.g. an inlined strcmp).

    When only a win sink is known (no failure string to anchor on -- e.g. a
    binary whose only classified outcome is "Success!" while the reject path
    prints something un-word-listed like "Error!"), fall back to a win-oriented
    rule: a branch is deciding when exactly one side can still reach the win, and
    that side is the one to force. This fallback is scoped to the no-lose case so
    it never changes selection where failure sinks already drive it."""
    g=cfg.graph; out=[]
    can_win=reverse_reachers(g, win)
    can_lose=reverse_reachers(g, lose)
    win_only = bool(win) and not lose
    for node in g.nodes():
        if not _is_ours(proj, node.addr): continue
        succ=list(g.successors(node))
        if len(succ)!=2: continue
        insns=node_insns(proj, node)
        if not insns or insns[-1].mnemonic not in ("je","jne","jz","jnz"): continue
        jmp=insns[-1]
        rw=[s in can_win for s in succ]; rl=[s in can_lose for s in succ]
        bad=None
        for k in (0,1):
            if rl[k] and not rw[k] and (rw[1-k] or not rl[1-k]):
                bad=k
        if bad is None and win_only:
            for k in (0,1):
                if rw[1-k] and not rw[k]:
                    bad=k
        if bad is None: continue
        try: jtarget=int(jmp.op_str,16)
        except Exception: jtarget=None
        bad_is_target = (succ[bad].addr==jtarget)
        out.append((jmp, not bad_is_target))   # take_jump = not bad_is_target
    return out

def _obj_basename(obj):
    return ((getattr(obj, "binary", "") or "?").replace("\\", "/")
            .rsplit("/", 1)[-1] or "?")

def _patchable_object(proj, addr, what="branch"):
    """Return the real, non-system loaded object that owns `addr`, or an
    explanatory skip reason. Patching must target the object that contains the
    selected branch -- in a whole-program call tree that can be a dependency,
    not necessarily the main executable."""
    obj=proj.loader.find_object_containing(addr)
    if obj is None or obj is getattr(proj.loader,"extern_object",None):
        return None, "%s address %#x is not in any loadable object" % (what, addr)
    binpath=getattr(obj,"binary","") or ""
    nm=_obj_basename(obj)
    if (not binpath) or "cle##" in binpath:
        return None, "%s is in angr scaffolding (%s), not a real file" % (what, nm)
    if obj is not proj.loader.main_object and is_system_module(binpath):
        return None, "refusing to patch a system/runtime module (%s)" % nm
    return obj, None

def _force_cond_jump(data, off, jmp, take_jump):
    """Patch a JE/JNE/JZ/JNZ at file offset `off` so execution always goes
    to the selected side. Supports both short (2-byte) and near (6-byte) x86
    conditional jumps, matching the dominance-gate patcher."""
    if off is None:
        return None, "could not map branch to a file offset"
    if off < 0 or off+jmp.size > len(data):
        return None, "mapped offset %#x is outside the file" % off
    if jmp.size==2 and data[off] in (0x74,0x75):      # short je/jne (jz/jnz aliases)
        if take_jump:
            data[off]=0xEB                            # -> jmp short, keep rel8
            return "EB(force take)", None
        data[off]=0x90; data[off+1]=0x90              # -> fall through
        return "90 90(force skip)", None
    if jmp.size==6 and data[off]==0x0f and data[off+1] in (0x84,0x85):
        if take_jump:
            # Original Jcc is 6 bytes and computes target from addr+6.  A near
            # JMP is 5 bytes, so the displacement must grow by one byte.
            rel=int.from_bytes(data[off+2:off+6],"little",signed=True)+1
            data[off]=0xE9
            data[off+1:off+5]=(rel & 0xffffffff).to_bytes(4,"little")
            data[off+5]=0x90
            return "E9(force take near) + NOP", None
        for k in range(6): data[off+k]=0x90            # -> fall through
        return "six NOPs(force skip)", None
    return None, "unsupported jump encoding (size %d, bytes %s)" % (
        jmp.size, bytes(data[off:off+jmp.size]).hex())

def _out_for_object(obj, out_arg, n_objs, used):
    nm=_obj_basename(obj)
    if out_arg:
        if out_arg.endswith(os.sep) or os.path.isdir(out_arg):
            os.makedirs(out_arg, exist_ok=True)
            out=os.path.join(out_arg, nm+".patched")
        elif n_objs==1:
            out=out_arg
        else:
            out="%s.%s.patched" % (out_arg, nm)
    else:
        out=nm+".patched"
    if out not in used:
        used.add(out); return out
    root,ext=os.path.splitext(out)
    if not ext: ext=".patched"
    i=2
    while True:
        cand="%s.%d%s" % (root, i, ext)
        if cand not in used:
            used.add(cand); return cand
        i+=1

def apply_branch_patches(proj, decisions, out_arg=None, title=None,
                         empty_msg="no conditional branches selected"):
    """Group selected branch patches by owning object and write one patched
    file per object. `decisions` is an iterable of (capstone_jump, take_jump).
    This is shared by the string-sink multi-branch patcher and the dominance
    gate fallback so selection and patch target cannot diverge."""
    if title: hr(title)
    decisions=list(decisions or [])
    if not decisions:
        print("  %s" % empty_msg); return False

    groups={}; skipped=0; seen=set()
    for jmp,take_jump in decisions:
        key=(jmp.address, bool(take_jump))
        if key in seen: continue
        seen.add(key)
        obj,why=_patchable_object(proj, jmp.address)
        if why:
            print("  skip %s @ %#x: %s" % (jmp.mnemonic, jmp.address, why))
            skipped+=1; continue
        groups.setdefault(obj,[]).append((jmp, bool(take_jump)))

    if not groups:
        print("  no selected branches are in patchable target objects")
        return False
    if len(groups)>1:
        print("  selected branches span %d objects; patching each file separately"
              % len(groups))

    used_out=set(); total_applied=0; objects_written=0
    for obj,items in groups.items():
        binpath=getattr(obj,"binary","") or ""
        nm=_obj_basename(obj)
        is_main = obj is proj.loader.main_object
        print("  object       : %s%s" % (nm, "  (main executable)" if is_main
                                      else "  (DEPENDENCY -- patching the library, not the app)"))
        try:
            with open(binpath,"rb") as f:
                data=bytearray(f.read())
        except Exception as e:
            print("    could not read %s: %s" % (binpath, e)); continue
        applied=0
        for jmp,take_jump in items:
            off=obj.addr_to_offset(jmp.address)
            how,err=_force_cond_jump(data, off, jmp, take_jump)
            if err:
                print("    skip %s @ %#x: %s" % (jmp.mnemonic, jmp.address, err))
                continue
            print("    %s @ %#x (off %#x) -> %s" %
                  (jmp.mnemonic, jmp.address, off, how))
            applied+=1
        if not applied:
            print("    no supported branch patch applied in %s" % nm)
            continue
        out=_out_for_object(obj, out_arg, len(groups), used_out)
        parent=os.path.dirname(out)
        if parent: os.makedirs(parent, exist_ok=True)
        with open(out,"wb") as f:
            f.write(data)
        try:
            shutil.copymode(binpath, out)
        except Exception:
            pass
        print("    wrote %s with %d branch patch(es) (original untouched)" % (out, applied))
        if not is_main:
            print("    NB: to use it, replace the library the app loads with %s"
                  " (e.g. copy over %s next to the app)." % (out, nm))
        total_applied+=applied; objects_written+=1

    if skipped:
        print("  skipped %d branch(es) outside patchable target objects" % skipped)
    print("  applied %d branch patch(es) across %d object file(s)"
          % (total_applied, objects_written))
    return total_applied>0

def patch(proj, cfg, win, lose, src=None, out_arg=None, title=None):
    decs=find_decisions(proj, cfg, win, lose)
    return apply_branch_patches(
        proj, decs, out_arg,
        title=title or "PATCH (uniform: neutralize every failure branch on the call tree)",
        empty_msg="no failure-only conditional branches isolated")

# ---------------------------------------------------------------------------

def _is_ours(proj, addr):
    o=proj.loader.find_object_containing(addr)
    if o is None or o is getattr(proj.loader,"extern_object",None): return False
    if o is proj.loader.main_object: return True
    nm=getattr(o,"binary","") or ""
    if not nm or "cle##" in nm: return False      # synthetic (externs/tls/kernel)
    return not is_system_module(nm)



def find_gate_dominance(proj, cfg):
    """No strings. Gate = the DEEPEST conditional branch whose one side
    DOMINATES a large fraction of our code -- every actual path to the body must
    pass through it. Uses true domination (must-pass), not mere reachability, so
    retry-loops ("wrong key, try again") that cycle back can't hide the gate.
    Fully architecture-agnostic: a standard dominator-tree computation on the
    whole-program CFG."""
    from collections import deque
    g=cfg.graph
    G=nx.DiGraph()
    for u in g.nodes():
        for v in g.successors(u): G.add_edge(u,v)
    entry=cfg.model.get_any_node(proj.entry)
    if entry is None or entry not in G: return None
    idom=nx.immediate_dominators(G, entry)
    dt=nx.DiGraph()
    for n,d in idom.items():
        if n is not d: dt.add_edge(d,n)
    our_ids=set(id(n) for n in G.nodes() if _is_ours(proj, n.addr))
    total=len(our_ids) or 1
    size={}
    for node in nx.dfs_postorder_nodes(dt, entry) if entry in dt else []:
        s=1 if id(node) in our_ids else 0
        for ch in dt.successors(node): s+=size.get(ch,0)
        size[node]=s
    def domsize(n): return size.get(n, 1 if id(n) in our_ids else 0)
    dist={id(entry):0}; dq=deque([entry])
    while dq:
        x=dq.popleft()
        for s in G.successors(x):
            if id(s) not in dist: dist[id(s)]=dist[id(x)]+1; dq.append(s)
    cands=[]
    for node in G.nodes():
        if id(node) not in our_ids: continue
        succ=list(G.successors(node))
        if len(succ)!=2: continue
        insns=node_insns(proj, node)
        if not insns or insns[-1].mnemonic not in ("je","jne","jz","jnz"): continue
        jmp=insns[-1]
        dA=domsize(succ[0]); dC=domsize(succ[1])
        big=max(dA,dC); small=min(dA,dC)
        if big < 4: continue
        if small > 0.30*big: continue     # gate is asymmetric: reject is a small
                                          # dead-end, not a loop back-edge (~symmetric)
        win_succ = succ[0] if dA>=dC else succ[1]
        lose_succ= succ[1] if dA>=dC else succ[0]
        depth=dist.get(id(node),-1)
        cands.append((depth, big, node.addr, jmp, win_succ.addr, lose_succ.addr, small))
    if not cands: return None
    max_big=max(c[1] for c in cands)
    spine=[c for c in cands if c[1] >= 0.6*max_big]
    spine.sort(key=lambda c:(c[0], c[1]))
    depth,big,baddr,jmp,waddr,laddr,small=spine[-1]
    return {"branch":baddr,"jmp":jmp,"win":waddr,"lose":laddr,
            "win_blocks":big,"lose_blocks":small,"pct":big/total,"total":total,
            "depth":depth,"n_gates":len(cands)}

def patch_gate(proj, gate, src=None, out_arg=None):
    hr("PATCH (force the dominance gate toward the unlocked side)")
    jmp=gate["jmp"]
    try: jtarget=int(jmp.op_str,16)
    except Exception: jtarget=None
    take=(gate["win"]==jtarget)   # win reached by TAKING the jump?
    print("  gate branch  : %s @ %#x ; win side = %s the jump" %
          (jmp.mnemonic, jmp.address, "TAKE" if take else "SKIP"))
    return apply_branch_patches(
        proj, [(jmp,take)], out_arg,
        empty_msg="no dominance gate branch selected")


# ---------------------------------------------------------------------------
# Taint qualification for the dominance gate (parity with the .NET gate path).
# Native has no typed booleans (C/C++ name-mangling makes the .NET overload trick
# irrelevant here), so the gate stays branch-level. What carries over is the
# QUALIFICATION: a gate matters when its condition is derived from an external
# source. We approximate that structurally -- a source-API call site must
# DOMINATE the gate (i.e. it must execute before every path that reaches the
# gate) -- which is the typeless analogue of ".NET local is source-tainted".
# ---------------------------------------------------------------------------
SOURCE_APIS = {
    "getenv","secure_getenv","GetEnvironmentVariableA","GetEnvironmentVariableW",
    "fopen","fopen64","open","open64","openat","CreateFileA","CreateFileW","_wfopen",
    "fgets","gets","getline","scanf","__isoc99_scanf","fscanf","__isoc99_fscanf",
    "read","fread","getchar","fgetc","recv","recvfrom","ReadFile",
    "RegQueryValueExA","RegQueryValueExW","RegGetValueA","RegGetValueW",
}

def _source_call_sites(proj, cfg):
    """Map {call-site node addr -> source api} for every call to a source API."""
    sites={}
    for f in cfg.functions.values():
        base=(f.name or "").split("@")[0]
        if base not in SOURCE_APIS: continue
        node=cfg.model.get_any_node(f.addr)
        if node is None: continue
        for pred in cfg.model.get_predecessors(node):
            sites.setdefault(pred.addr, base)
    return sites

def gate_source_taint(proj, cfg, gate):
    """(tainted, source): is a source-API call site a dominator of the gate? This
    is the structural taint check -- the gate condition must derive from input
    that was read upstream of the branch on every path."""
    if not gate: return False, None
    sites=_source_call_sites(proj, cfg)
    if not sites: return False, None
    G=nx.DiGraph()
    for u in cfg.graph.nodes():
        for v in cfg.graph.successors(u): G.add_edge(u,v)
    entry=cfg.model.get_any_node(proj.entry)
    gnode=cfg.model.get_any_node(gate["branch"])
    if entry is None or gnode is None or entry not in G or gnode not in G:
        return False, None
    try: idom=nx.immediate_dominators(G, entry)
    except Exception: return False, None
    cur=gnode; seen=set()
    while cur is not None and id(cur) not in seen:     # walk gate -> ... -> entry
        seen.add(id(cur))
        if cur.addr in sites: return True, sites[cur.addr]
        nxt=idom.get(cur)
        if nxt is cur: break
        cur=nxt
    return False, None


# ---------------------------------------------------------------------------
# Native angr frontend wrapper (used by the refactored top-level CLI)
# ---------------------------------------------------------------------------
class NativeAngrFrontend(AnalyzerFrontend):
    """Native ELF/PE backend backed by angr.

    This class wraps the original architecture-agnostic native pipeline so the
    top-level CLI can route native targets to angr and runtime/managed targets
    to dedicated frontends.
    """
    def __init__(self, binary, options=None):
        self.options=options or AnalyzerOptions()
        self.binary=binary
        self.force_low_confidence=self.options.force_low_confidence
        self.proj,self.cfg=load_calltree(binary)
        self.os_,self.files,self.envs,self.regs=detect_sources(self.proj,self.cfg)
        self.gate=None
        self.sink_win=None
        self.sink_lose=None

    def header(self, mode):
        print("target: %s   mode: %s   os: %s   (call tree: %d functions across %d objects)"
              % (self.binary, mode, self.os_, len(list(self.cfg.functions)), len(self.proj.loader.all_objects)))

    def print_objects(self):
        hr("CALL-TREE OBJECTS (+ counted as 'ours', - platform/runtime)")
        for o in self.proj.loader.all_objects:
            if o is getattr(self.proj.loader,"extern_object",None): continue
            nm=(getattr(o,"binary","") or "?").rsplit("/",1)[-1]
            binpath=getattr(o,"binary","") or ""
            synthetic = (not binpath) or ("cle##" in binpath)
            if o is self.proj.loader.main_object:
                tag,main_tag="+","  (main executable)"
            elif synthetic:
                tag,main_tag="·",""
            else:
                tag,main_tag=("+" if not is_system_module(binpath) else "-"),""
            print("  %s %#012x-%#012x  %s%s" % (tag, o.min_addr, o.max_addr, nm, main_tag))

    def runtime_info(self):
        return detect_runtime(self.proj,self.cfg,self.binary,self.os_,self.files,self.envs,self.regs)

    def _ensure_gate(self):
        if self.gate is None:
            self.gate=find_gate_dominance(self.proj,self.cfg)
        return self.gate

    def _print_gate_report(self):
        gate=self._ensure_gate()
        hr("GATE BY DOMINANCE (no strings -- how much code each side unlocks)")
        if not gate:
            print("  no dominating conditional branch found")
            return None, False, True
        gname,gmain = obj_of(self.proj, gate["jmp"].address)
        wname,_     = obj_of(self.proj, gate["win"])
        lname,_     = obj_of(self.proj, gate["lose"])
        print("  gate branch  : %s @ %#x   [%s]%s"
              % (gate["jmp"].mnemonic, gate["jmp"].address, gname,
                 "" if gmain else "   <-- NOT in main executable"))
        print("  unlocked side: %#x  [%s]  (reaches %d of %d our-blocks = %.0f%% of code)"
              % (gate["win"], wname, gate["win_blocks"], gate["total"], 100*gate["pct"]))
        print("  rejected side: %#x  [%s]  (reaches only %d blocks)"
              % (gate["lose"], lname, gate["lose_blocks"]))
        print("  input sources: files=%s envs=%s registry=%s (+stdin always)"
              % (self.files,self.envs,self.regs))
        low_conf = gate["pct"] < 0.05
        if low_conf:
            print("  WARNING: unlocked side is only %.0f%% of code -- this is almost"
                  " certainly NOT a real license gate." % (100*gate["pct"]))
            print("           No asymmetric gate was found; the dominance picker fell"
                  " back to the deepest branch passing a *relative* threshold, i.e.")
            print("           noise. Treat this address as meaningless. (A target with"
                  " no license check -- e.g. a runtime host -- looks exactly like this.)")
        if not gmain:
            print("  NOTE: the gate lives in a dependency, not the main executable;"
                  " confirm that dependency is actually the target you mean to analyze.")
        return gate, low_conf, False

    def _solve_target(self, gate):
        """Prefer real outcome sinks when available; otherwise solve to the gate's
        unlocked successor. This avoids targeting unrelated large helper/init
        functions, which creates spurious symbolic "solutions"."""
        self.sink_win,self.sink_lose,_seen=outcome_sinks(self.proj,self.cfg)
        if self.sink_win:
            return set(self.sink_win)
        return {gate["win"]}

    def report(self):
        self._print_gate_report()
        return True

    def plan_patch(self):
        self._print_gate_report()
        self._print_patch_plan()
        self._print_gate_taint_plan()
        return True

    def _gate_candidates_neutral(self):
        """Lower the native dominance gate to the shared GateCandidate, qualified
        by dominator-chain taint. Native stays branch-level (no typed value to
        force), which the shared model captures via force_value=None."""
        gate=self._ensure_gate()
        if not gate: return []
        jmp=gate["jmp"]
        try: jtarget=int(jmp.op_str,16)
        except Exception: jtarget=None
        take=(gate["win"]==jtarget)            # is the unlocked side reached by jumping?
        tainted,source=gate_source_taint(self.proj,self.cfg,gate)
        fn=self.cfg.functions.floor_func(gate["branch"])
        unit=(fn.name if fn else None) or ("sub_%x" % gate["branch"])
        notes=["native gate is branch-level (no typed bool); patched by forcing the"
               " conditional, not a value"]
        if not tainted:
            notes.append("no source-API call site dominates the gate; taint UNCONFIRMED"
                         " (gate kept on dominance significance alone)")
        return [GateCandidate(
            backend="native", unit=unit, kind="dominance",
            gate_locator="%s @ %#x" % (jmp.mnemonic, jmp.address),
            gate_sites=["%#x" % jmp.address],
            tainted=tainted, source=source, flows_through=[],
            licensed_side=("take jump -> %#x" % gate["win"]) if take
                          else ("fall through -> %#x" % gate["win"]),
            significance=gate.get("pct"),
            patch_target="force %s @ %#x toward the unlocked side (%s)"
                         % (jmp.mnemonic, jmp.address, "TAKE" if take else "SKIP"),
            force_value=None, notes=notes)]

    def _print_gate_taint_plan(self):
        return render_plan("NATIVE TAINTED-GATE PLAN (typeless; preview, no bytes written)",
                           self._gate_candidates_neutral())

    def _print_patch_plan(self):
        """Non-destructive preview of the branches `--mode patch` would
        neutralize (driven by --mode plan-patch). Selection only; nothing is written.
        Mirrors patch()'s selection order: outcome sinks first, then the
        dominance gate, then the single-gate fallback."""
        hr("PATCH PLAN (branches --mode patch would neutralize; nothing written)")
        gate=self._ensure_gate()
        self.sink_win,self.sink_lose,_seen=outcome_sinks(self.proj,self.cfg)
        decs=[]
        if self.sink_win or self.sink_lose:
            print("  outcome sinks: win=%d lose=%d" % (len(self.sink_win or ()), len(self.sink_lose or ())))
            decs=find_decisions(self.proj,self.cfg,self.sink_win or set(),self.sink_lose or set())
        if not decs and gate:
            decs=find_decisions(self.proj,self.cfg,{gate["win"]},{gate["lose"]})
        if decs:
            for jmp,take in decs:
                print("    %s @ %#x -> %s" % (jmp.mnemonic, jmp.address,
                      "force TAKE (jump to win side)" if take else "force SKIP (fall through to win side)"))
            print("  status: preview only; run --mode patch to apply.")
        elif gate:
            jmp=gate["jmp"]
            try: jtarget=int(jmp.op_str,16)
            except Exception: jtarget=None
            take=(gate["win"]==jtarget)
            print("  no failure-only branches isolated; would force the dominance gate:")
            print("    %s @ %#x -> %s" % (jmp.mnemonic, jmp.address, "force TAKE" if take else "force SKIP"))
            print("  status: preview only; run --mode patch to apply.")
        else:
            print("  no win/lose outcome sinks or dominance gate identified; nothing to flip")

    def solve(self, force_low_confidence=None):
        if force_low_confidence is None:
            force_low_confidence=self.force_low_confidence
        gate,low_conf,no_gate=self._print_gate_report()
        if no_gate: print(); return False
        if low_conf and not force_low_confidence:
            print("  refusing to solve a low-confidence candidate; rerun with"
                  " --force-low-confidence only for an authorized research target.")
            print(); return False
        solve_win=self._solve_target(gate)
        lose=set(self.sink_lose) if self.sink_lose else {gate["lose"]}
        solve(self.proj,self.cfg,solve_win,lose,self.files,self.envs,self.regs,self.binary,os_=self.os_)
        return True


    def patch(self, out_arg=None, force_low_confidence=None):
        if force_low_confidence is None:
            force_low_confidence=self.force_low_confidence
        gate,low_conf,no_gate=self._print_gate_report()
        if no_gate:
            self.sink_win,self.sink_lose,_seen=outcome_sinks(self.proj,self.cfg)
            if self.sink_win or self.sink_lose:
                print("  outcome sinks: win=%d lose=%d" % (len(self.sink_win or ()), len(self.sink_lose or ())))
                return patch(self.proj,self.cfg,self.sink_win or set(),self.sink_lose or set(),self.binary,out_arg,
                             title="PATCH (outcome sinks: neutralize every failure-only branch)")
            hr("PATCH (uniform: neutralize every failure branch on the call tree)")
            print("  no win/lose outcome sinks identified; cannot select failure-only branches")
            print(); return False
        if low_conf and not force_low_confidence:
            print("  refusing to patch a low-confidence candidate; rerun with"
                  " --force-low-confidence only for an authorized research target.")
            print(); return False
        self.sink_win,self.sink_lose,_seen=outcome_sinks(self.proj,self.cfg)
        patched=False
        if self.sink_win or self.sink_lose:
            print("  outcome sinks: win=%d lose=%d" % (len(self.sink_win or ()), len(self.sink_lose or ())))
            patched=patch(self.proj,self.cfg,self.sink_win or set(),self.sink_lose or set(),self.binary,out_arg,
                          title="PATCH (outcome sinks: neutralize every failure-only branch)")
            if not patched:
                print("  falling back to dominance-derived branch selection")
        else:
            print("  no win/lose outcome sinks identified; using dominance-derived branch selection")
        if not patched:
            patched=patch(self.proj,self.cfg,{gate["win"]},{gate["lose"]},self.binary,out_arg,
                          title="PATCH (dominance: neutralize every branch to the rejected side)")
        if not patched:
            print("  falling back to the single dominance gate patch")
            patched=patch_gate(self.proj,gate,self.binary,out_arg)
        return patched
