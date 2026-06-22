"""Tiny CIL assembler shared by tests. Produces REAL opcode bytes with correct
sizes for the (small but commonly used) opcode subset listed in OPC.

A program is a list of items where each item is one of:
    ("@label",)                       -- label marker, takes zero bytes
    (op,)                             -- opcode with no operand
    (op, {"text": ...})               -- ldstr / call with a generated token
    (op, {"text": ..., "tok": ...})   -- ldstr / call with a forced token
    (op, {"label": "LABEL"})          -- short branch to a label
    (op, {"label": "LABEL", "long": True}) -- long-form branch (4-byte disp)
    (op, {"u1": N})                   -- 1-byte immediate (e.g. ldloc.s)
    (op, {"i1": N})                   -- signed 1-byte immediate (e.g. ldc.i4.s)
    (op, {"i4": N})                   -- signed 4-byte immediate (e.g. ldc.i4)

The assembler returns (code_bytes, strmap, callmap, labels).
"""
import struct

OPC_ONE = {
    "nop": 0x00, "break": 0x01,
    "ldarg.0": 0x02, "ldarg.1": 0x03, "ldarg.2": 0x04, "ldarg.3": 0x05,
    "ldloc.0": 0x06, "ldloc.1": 0x07, "ldloc.2": 0x08, "ldloc.3": 0x09,
    "stloc.0": 0x0A, "stloc.1": 0x0B, "stloc.2": 0x0C, "stloc.3": 0x0D,
    "ldarg.s": 0x0E, "ldloca.s": 0x12, "ldloc.s": 0x11, "stloc.s": 0x13,
    "ldnull": 0x14,
    "ldc.i4.m1": 0x15, "ldc.i4.0": 0x16, "ldc.i4.1": 0x17, "ldc.i4.2": 0x18,
    "ldc.i4.3": 0x19, "ldc.i4.4": 0x1A, "ldc.i4.5": 0x1B, "ldc.i4.6": 0x1C,
    "ldc.i4.7": 0x1D, "ldc.i4.8": 0x1E, "ldc.i4.s": 0x1F, "ldc.i4": 0x20,
    "dup": 0x25, "pop": 0x26, "call": 0x28, "ret": 0x2A,
    "br.s": 0x2B, "brfalse.s": 0x2C, "brtrue.s": 0x2D,
    "beq.s": 0x2E, "bge.s": 0x2F, "bgt.s": 0x30, "ble.s": 0x31, "blt.s": 0x32,
    "bne.un.s": 0x33,
    "br": 0x38, "brfalse": 0x39, "brtrue": 0x3A,
    "beq": 0x3B, "bge": 0x3C, "bgt": 0x3D, "ble": 0x3E, "blt": 0x3F, "bne.un": 0x40,
    "add": 0x58, "sub": 0x59, "mul": 0x5A, "and": 0x5F, "or": 0x60, "xor": 0x61,
    "neg": 0x65, "not": 0x66,
    "callvirt": 0x6F, "ldstr": 0x72, "newobj": 0x73,
    "throw": 0x7A,
}
OPC_TWO = {  # 0xFE prefix
    "ceq": 0x01, "cgt": 0x02, "cgt.un": 0x03, "clt": 0x04, "clt.un": 0x05,
}

# Operand kind by opcode (for size + emit).
def _kind(op):
    if op in ("call", "callvirt", "newobj", "ldstr"):
        return "token"
    if op in ("ldarg.s", "ldloc.s", "stloc.s", "ldloca.s"):
        return "u1"
    if op == "ldc.i4.s":
        return "i1"
    if op == "ldc.i4":
        return "i4"
    if op.endswith(".s") and op not in ("ldc.i4.s",) and op[:-2] in (
        "br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt", "bne.un"
    ):
        return "br1"
    if op in ("br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt", "bne.un"):
        return "br4"
    return "none"

_SIZE = {"none": 0, "u1": 1, "i1": 1, "i4": 4, "token": 4, "br1": 1, "br4": 4}


def _instr_size(op):
    base = 2 if op in OPC_TWO else 1
    return base + _SIZE[_kind(op)]


def assemble(prog):
    """Assemble a tiny CIL program. See module docstring for the item shapes."""
    # Pass 1: lay out, collect labels.
    off = 0
    labels = {}
    layout = []
    for it in prog:
        if it[0].startswith("@"):
            labels[it[0][1:]] = off
            continue
        op = it[0]
        attrs = it[1] if len(it) > 1 else {}
        layout.append((off, op, attrs))
        off += _instr_size(op)

    code = bytearray()
    strmap = {}
    callmap = {}
    next_str_tok = 0x70000001
    next_call_tok = 0x06000001

    for o, op, a in layout:
        # Emit opcode bytes.
        if op in OPC_TWO:
            code.append(0xFE)
            code.append(OPC_TWO[op])
        else:
            code.append(OPC_ONE[op])
        kind = _kind(op)

        if kind == "none":
            continue
        if kind == "token":
            if op == "ldstr":
                tok = a.get("tok", next_str_tok)
                next_str_tok = max(next_str_tok, tok + 1)
                strmap[tok] = a.get("text", "")
            else:
                tok = a.get("tok", next_call_tok)
                next_call_tok = max(next_call_tok, tok + 1)
                callmap[tok] = a.get("text", "")
            code += struct.pack("<I", tok)
        elif kind == "u1":
            code += struct.pack("B", int(a.get("u1", 0)) & 0xff)
        elif kind == "i1":
            code += struct.pack("b", int(a.get("i1", 0)))
        elif kind == "i4":
            code += struct.pack("<i", int(a.get("i4", 0)))
        elif kind in ("br1", "br4"):
            lbl = a["label"]
            tgt = labels[lbl]
            after = o + _instr_size(op)
            disp = tgt - after
            if kind == "br1":
                code += struct.pack("b", disp)
            else:
                code += struct.pack("<i", disp)
    return bytes(code), strmap, callmap, labels


def decode_with(decode_fn, prog):
    """Assemble prog, decode with the backend's _decode_cil(code, pe=None),
    then post-resolve ldstr/call .text from the assembler's maps."""
    code, strmap, callmap, labels = assemble(prog)
    ins = decode_fn(code, None)
    for x in ins:
        if x["op"] == "ldstr":
            x["text"] = strmap.get(x["operand"])
        elif x["op"] in ("call", "callvirt", "newobj"):
            x["text"] = callmap.get(x["operand"])
    return code, ins, labels


def build_method(decode_fn, name, prog):
    """Build a method dict like _decode_methods produces."""
    code, ins, _ = decode_with(decode_fn, prog)
    calls = [x["text"] for x in ins if x["op"] in ("call", "callvirt", "newobj") and x.get("text")]
    strings = [x["text"] for x in ins if x["op"] == "ldstr" and x.get("text")]
    return code, {
        "name": name,
        "ins": ins,
        "body": {"code_off": 0, "code_size": len(code), "more_sects": False},
        "calls": calls,
        "strings": strings,
    }
