"""Decoder tests for _decode_cil and friends.

These cover:
  * single-byte and 0xFE-prefixed two-byte opcodes
  * operand sizes (u1, i1, i4, token, br1, br4, switch)
  * branch target resolution
  * round-trip: every instruction's `end` matches the next `off`
  * unknown opcodes do not crash and still advance one byte
"""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from calltree_backends.dotnet_il import _decode_cil
from tests._assembler import assemble, decode_with, OPC_ONE

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("  FAIL:", msg)
    else:
        print("  ok  :", msg)


def test_basic_opcodes_round_trip():
    prog = [
        ("nop",), ("ldc.i4.3",), ("stloc.0",), ("ldloc.0",), ("ret",)
    ]
    code, ins, _ = decode_with(_decode_cil, prog)
    ops = [x["op"] for x in ins]
    check(ops == ["nop", "ldc.i4.3", "stloc.0", "ldloc.0", "ret"],
          "basic opcodes decoded in order: %r" % ops)
    # off/end contiguous
    for a, b in zip(ins, ins[1:]):
        check(a["end"] == b["off"], "off/end contiguous: %r" % (ops,))
    check(ins[-1]["end"] == len(code), "last instr ends at code end")


def test_two_byte_ceq():
    code, _, _, _ = assemble([("ldc.i4.0",), ("ldc.i4.0",), ("ceq",), ("ret",)])
    ins = _decode_cil(code, None)
    check([x["op"] for x in ins] == ["ldc.i4.0", "ldc.i4.0", "ceq", "ret"],
          "0xFE 0x01 ceq decoded")
    check(ins[2]["size"] == 2, "ceq size == 2 bytes")


def test_operand_sizes_u1_i1_i4():
    # ldloc.s 5 ; ldc.i4.s -3 ; ldc.i4 12345 ; pop ; ret
    code = bytes([0x11, 5, 0x1F]) + struct.pack("b", -3) + bytes([0x20]) + struct.pack("<i", 12345) + bytes([0x26, 0x2A])
    ins = _decode_cil(code, None)
    ops = [x["op"] for x in ins]
    check(ops == ["ldloc.s", "ldc.i4.s", "ldc.i4", "pop", "ret"], "operand-size opcodes: %r" % ops)
    check(ins[0]["operand"] == 5, "ldloc.s operand decoded as u1=5")
    check(ins[1]["operand"] == -3, "ldc.i4.s operand decoded as i1=-3")
    check(ins[2]["operand"] == 12345, "ldc.i4 operand decoded as i4=12345")


def test_token_operands():
    prog = [("ldstr", {"text": "hello"}), ("call", {"text": "X::Y"}), ("ret",)]
    code, ins, _ = decode_with(_decode_cil, prog)
    check(ins[0]["op"] == "ldstr" and ins[0]["text"] == "hello", "ldstr text resolved via map")
    check(ins[1]["op"] == "call" and ins[1]["text"] == "X::Y", "call text resolved via map")
    check(ins[0]["size"] == 5 and ins[1]["size"] == 5, "token operands are 4 bytes (+1 op)")


def test_branch_targets_short_and_long():
    prog = [
        ("ldc.i4.0",),
        ("brfalse.s", {"label": "L"}),
        ("nop",),
        ("@L",),
        ("ret",),
    ]
    code, ins, labels = decode_with(_decode_cil, prog)
    br = [x for x in ins if x["op"] == "brfalse.s"][0]
    check(br["target"] == labels["L"], "brfalse.s target resolved: %r vs %r" % (br["target"], labels["L"]))

    prog2 = [("ldc.i4.0",), ("brtrue", {"label": "M"}), ("nop",), ("@M",), ("ret",)]
    code2, ins2, labels2 = decode_with(_decode_cil, prog2)
    br2 = [x for x in ins2 if x["op"] == "brtrue"][0]
    check(br2["size"] == 5, "long-form brtrue is 5 bytes (op+4)")
    check(br2["target"] == labels2["M"], "long-form brtrue target resolved")


def test_switch_decoding():
    # switch (3 targets at +2, +4, +6) ; nop x10 ; ret
    targets = [2, 4, 6]
    payload = bytes([0x45]) + struct.pack("<I", len(targets)) + struct.pack("<3i", *targets)
    code = payload + bytes([0x00] * 10) + bytes([0x2A])
    ins = _decode_cil(code, None)
    sw = ins[0]
    check(sw["op"] == "switch", "switch decoded")
    check(isinstance(sw["target"], list) and len(sw["target"]) == 3, "switch has 3 absolute targets")
    end_off = sw["end"]
    check(sw["target"] == [end_off + t for t in targets], "switch targets are end-relative absolute")


def test_unknown_opcode_does_not_crash():
    # 0xa9 is unassigned in our table; decoder should label it unknown.<hex>
    # and advance one byte (its operand kind is "none" by fallback).
    code = bytes([0xA9, 0x2A])  # unknown, ret
    ins = _decode_cil(code, None)
    check(len(ins) == 2 and ins[0]["op"].startswith("unknown."),
          "unknown opcode produces unknown.* label: %r" % ins[0]["op"])
    check(ins[1]["op"] == "ret", "decoder kept going past unknown opcode")


def test_empty_code():
    ins = _decode_cil(b"", None)
    check(ins == [], "empty code -> empty instr list")


def main():
    for fn in [test_basic_opcodes_round_trip, test_two_byte_ceq, test_operand_sizes_u1_i1_i4,
               test_token_operands, test_branch_targets_short_and_long, test_switch_decoding,
               test_unknown_opcode_does_not_crash, test_empty_code]:
        print("\n--", fn.__name__)
        fn()
    if FAILS:
        print("\nDECODER: %d failure(s)" % len(FAILS))
        for f in FAILS: print("  -", f)
        return 1
    print("\nDECODER: all OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
