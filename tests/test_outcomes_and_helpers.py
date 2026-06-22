"""Tests for outcome classification, basic blocks, value-region calc, stack
deltas, and the helper-aware constant evaluator."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from calltree_backends.dotnet_il import DotNetILFrontend, _decode_cil
from calltree_backends import outcomes
from tests._assembler import build_method, assemble

FAILS = []

def check(cond, msg):
    if not cond: FAILS.append(msg); print("  FAIL:", msg)
    else: print("  ok  :", msg)

fe = DotNetILFrontend.__new__(DotNetILFrontend)


def test_outcomes_classify():
    wins, loses, other = outcomes.classify_strings([
        "License accepted. Welcome!", "License invalid. Access denied.",
        "checksum is not correct", "hello world", "Premium unlocked.",
        "wrong key", None,
    ])
    check("License accepted. Welcome!" in wins, "win phrase classified as win")
    check("License invalid. Access denied." in loses, "lose phrase classified as lose")
    check("checksum is not correct" in loses,
          "negative wins precedence: 'not correct' is lose, not win")
    check("hello world" in other, "neutral string is other")
    check("Premium unlocked." in wins, "unlocked -> win")
    check("wrong key" in loses, "wrong -> lose")


def test_dotnet_strings_noise_filter():
    wf = DotNetILFrontend.__new__(DotNetILFrontend)
    # Generated/identifier-ish names should be filtered to 'other'.
    wins, loses, other = wf._classify_strings([
        "Program.<Main>d__0", "Foo.Bar.Baz", "License accepted welcome",
        "x" * 200, "ok",
    ])
    check("Program.<Main>d__0" in other, "<...>d__0 noise -> other")
    check("Foo.Bar.Baz" in other, "dotted identifier (no spaces) -> other")
    check("License accepted welcome" in wins, "still classifies real win phrase")
    check(("x" * 200) in other, "overly long string -> other (noise filter)")


def test_basic_blocks_split():
    code, m = build_method(_decode_cil, "BB", [
        ("ldc.i4.0",),
        ("brfalse.s", {"label": "el"}),
        ("ldc.i4.1",), ("ret",),
        ("@el",), ("ldc.i4.0",), ("ret",),
    ])
    blocks, off_to_idx = fe._basic_blocks(m["ins"])
    # Expect three blocks: entry (ldc.i4.0+brfalse.s), then-block, else-block.
    check(len(blocks) == 3, "three basic blocks: %r" % (blocks,))
    # Each block ends with a terminator.
    for s, e in blocks:
        term = m["ins"][e - 1]["op"]
        check(term in ("brfalse.s", "ret"), "block terminator is br*/ret, got %r" % term)


def test_stack_delta_known_and_unknown_call():
    # Build a call to an unknown name -> _call_stack_delta returns None
    code, m = build_method(_decode_cil, "X", [
        ("ldarg.0",), ("call", {"text": "Unknown::Mystery"}), ("pop",), ("ret",),
    ])
    ins = m["ins"]
    d = fe._stack_delta(ins[1])
    check(d is None, "unknown call has None stack delta (refuses to guess)")
    # Known: op_Inequality is -1 (pops 2, pushes 1).
    code2, m2 = build_method(_decode_cil, "Y", [
        ("ldarg.0",), ("ldstr", {"text": "k"}),
        ("call", {"text": "System.String::op_Inequality"}),
        ("pop",), ("ret",),
    ])
    d2 = fe._stack_delta(m2["ins"][2])
    check(d2 == -1, "op_Inequality stack delta is -1, got %r" % d2)


def test_value_region_simple():
    # Region for stloc.0 should cover the value computation (ldc.i4.3 here).
    code, m = build_method(_decode_cil, "VR", [
        ("ldc.i4.3",), ("stloc.0",), ("ret",),
    ])
    blocks, _ = fe._basic_blocks(m["ins"])
    idx_to_block = {}
    for bi, (s, e) in enumerate(blocks):
        for j in range(s, e): idx_to_block[j] = bi
    def_idx = 1  # the stloc.0
    region = fe._value_region(m["ins"], blocks, idx_to_block, def_idx)
    check(region is not None, "region found")
    s_off, e_off = region
    check(s_off == m["ins"][0]["off"] and e_off == m["ins"][1]["off"],
          "region = [ldc.i4.3, stloc.0): got %r" % (region,))


def test_value_region_refuses_unknown_call():
    # An unknown-arity call in the region must produce None (byte-safety).
    code, m = build_method(_decode_cil, "VRN", [
        ("call", {"text": "Some::Unknown"}),  # unknown delta
        ("stloc.0",), ("ret",),
    ])
    blocks, _ = fe._basic_blocks(m["ins"])
    idx_to_block = {j: 0 for j in range(len(m["ins"]))}
    region = fe._value_region(m["ins"], blocks, idx_to_block, 1)
    check(region is None, "value_region refuses when an unknown call sits inside")


def test_helper_eval_flip_bool():
    # Flip(bool) := ldarg.0; ldc.i4.0; ceq; ret  -- returns 1 if arg==0 else 0.
    code, _, _, _ = assemble([
        ("ldarg.0",), ("ldc.i4.0",), ("ceq",), ("ret",),
    ])
    ins = _decode_cil(code, None)
    check(fe._eval_il_const(ins, 0) == 1, "Flip(false) == true")
    check(fe._eval_il_const(ins, 1) == 0, "Flip(true) == false")


def test_helper_eval_neg_int():
    # Flip(int) := ldarg.0; neg; ret  -- returns -arg.
    code, _, _, _ = assemble([("ldarg.0",), ("neg",), ("ret",)])
    ins = _decode_cil(code, None)
    check(fe._eval_il_const(ins, 3) == -3, "neg(3) == -3")
    check(fe._eval_il_const(ins, -7) == 7, "neg(-7) == 7")


def test_helper_eval_gives_up_on_unmodelled():
    # A call inside the helper is not modelled -> None.
    code, _, _, _ = assemble([
        ("ldarg.0",), ("call", {"text": "Whatever::Mystery"}), ("ret",),
    ])
    ins = _decode_cil(code, None)
    check(fe._eval_il_const(ins, 1) is None,
          "evaluator returns None for unmodelled call (no false constants)")


def test_helper_eval_handles_malformed():
    # 'neg' on an empty stack would raise IndexError inside _eval_il_const; the
    # function MUST return None instead of crashing, per its docstring.
    code, _, _, _ = assemble([("neg",), ("ret",)])
    ins = _decode_cil(code, None)
    res = fe._eval_il_const(ins, 0)
    check(res is None, "helper evaluator returns None on stack underflow, got %r" % res)


def test_cond_branch_pop_count():
    check(fe._branch_pop_count("brtrue.s") == 1, "brtrue.s pops 1")
    check(fe._branch_pop_count("brfalse") == 1, "brfalse pops 1")
    check(fe._branch_pop_count("beq.s") == 2, "beq.s pops 2")
    check(fe._branch_pop_count("bne.un") == 2, "bne.un pops 2")
    check(fe._branch_pop_count("ret") is None, "ret has no defined pop count for branch flip")


def main():
    fns = [test_outcomes_classify, test_dotnet_strings_noise_filter, test_basic_blocks_split,
           test_stack_delta_known_and_unknown_call, test_value_region_simple,
           test_value_region_refuses_unknown_call, test_helper_eval_flip_bool,
           test_helper_eval_neg_int, test_helper_eval_gives_up_on_unmodelled,
           test_helper_eval_handles_malformed, test_cond_branch_pop_count]
    for fn in fns:
        print("\n--", fn.__name__); fn()
    if FAILS:
        print("\nHELPERS: %d failure(s)" % len(FAILS))
        for f in FAILS: print("  -", f)
        return 1
    print("\nHELPERS: all OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
