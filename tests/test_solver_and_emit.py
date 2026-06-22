"""End-to-end tests for the bounded symbolic IL solver and gate-force emitter.

The bounded solver is the z3-backed path that takes a small method that compares
its argument against an ldstr constant and produces a satisfying input string.
"""
import os, sys, tempfile, io, contextlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from calltree_backends.dotnet_il import DotNetILFrontend, _decode_cil
from calltree_backends import gates as gates_mod
from tests._assembler import build_method, assemble

FAILS = []
def check(cond, msg):
    if not cond: FAILS.append(msg); print("  FAIL:", msg)
    else: print("  ok  :", msg)


def fresh_fe():
    fe = DotNetILFrontend.__new__(DotNetILFrontend)
    fe.options = type("O", (), {"il_dump": False, "method_filter": None, "force_low_confidence": False})()
    fe.method_filter = None
    fe.il_dump = False
    fe._token_methods = {}
    return fe


EQ = "System.String::op_Equality"
WL = "System.Console::WriteLine"
RD = "System.Console::ReadLine"


def test_bounded_solver_recovers_constant():
    """A CheckLicense-shape method: arg0 == "MAGIC" -> return true.
    The bounded solver must yield "MAGIC"."""
    fe = fresh_fe()
    prog = [
        ("ldarg.0",), ("ldstr", {"text": "MAGIC"}), ("call", {"text": EQ}),
        ("brfalse.s", {"label": "lose"}),
        ("ldc.i4.1",), ("ret",),
        ("@lose",), ("ldc.i4.0",), ("ret",),
    ]
    _, m = build_method(_decode_cil, "CheckLicense", prog)
    sols = fe._execute_symbolic_method(m, max_paths=32, max_steps=400, max_len=16)
    check("MAGIC" in sols, "bounded solver should find 'MAGIC'; got %r" % sols)


def test_emit_refuses_when_no_force_const():
    """When the helper chain is not evaluable, force_const stays None and the
    writer must NOT touch the file."""
    fe = fresh_fe()
    # Resolve helper to something with an unmodelled op (so eval returns None).
    BAD_HELPER = 0x06000901
    fe._token_methods = {
        BAD_HELPER: _decode_cil(
            bytes([0x02, 0x28]) + (0x06000999).to_bytes(4, "little") + bytes([0x2A]),
            None,
        ),
    }
    ENV = "System.Environment::GetEnvironmentVariable"
    NEQ = "System.String::op_Inequality"
    prog = [
        ("ldstr", {"text": "K"}), ("call", {"text": ENV}), ("stloc.0",),
        ("ldloc.0",), ("ldstr", {"text": "X"}), ("call", {"text": NEQ}), ("stloc.1",),
        ("ldloc.1",), ("call", {"text": "Program::Bad", "tok": BAD_HELPER}),
        ("brfalse.s", {"label": "el"}),
        ("ldstr", {"text": "License accepted welcome"}), ("call", {"text": WL}),
        ("ret",),
        ("@el",), ("ldstr", {"text": "denied invalid"}), ("call", {"text": WL}),
        ("ret",),
    ]
    code, m = build_method(_decode_cil, "M", prog)
    cands = fe._gate_taint_candidates(m)
    check(len(cands) == 1, "still finds the gate candidate")
    check(cands[0]["force_const"] is None, "force_const remains None when helper unmodelled")
    with tempfile.TemporaryDirectory() as d:
        prim = os.path.join(d, "x.dll"); open(prim, "wb").write(code)
        fe.primary = prim
        out = os.path.join(d, "x.patched.dll")
        wrote, _ = fe._emit_gate_forces([m], out_arg=out)
        check(wrote is False, "emit refuses without a force constant")
        check(not os.path.exists(out), "no patched file written when refusing")


def test_render_plan_outputs_expected_lines():
    """The shared gate-plan renderer must print the standard fields when given
    a typed-local + inlined neutral candidate pair."""
    fe = fresh_fe()
    FLIP_BOOL = 0x06000ABC
    fe._token_methods = {FLIP_BOOL: _decode_cil(bytes([0x02, 0x16, 0xFE, 0x01, 0x2A]), None)}
    ENV = "System.Environment::GetEnvironmentVariable"
    NEQ = "System.String::op_Inequality"
    prog = [
        ("ldstr", {"text": "K"}), ("call", {"text": ENV}), ("stloc.0",),
        ("ldloc.0",), ("ldstr", {"text": "X"}), ("call", {"text": NEQ}), ("stloc.1",),
        ("ldloc.1",), ("call", {"text": "Program::Flip", "tok": FLIP_BOOL}),
        ("brfalse.s", {"label": "el"}),
        ("ldstr", {"text": "License accepted welcome"}), ("call", {"text": WL}),
        ("ret",),
        ("@el",), ("ldstr", {"text": "denied invalid"}), ("call", {"text": WL}),
        ("ret",),
    ]
    _, m = build_method(_decode_cil, "M", prog)
    cands = fe._gate_taint_candidates(m)
    neutrals = [fe._to_neutral(c) for c in cands]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = gates_mod.render_plan("TEST PLAN", neutrals)
    out = buf.getvalue()
    check(ok is True, "render_plan returns True with candidates")
    check("TEST PLAN" in out, "plan title is printed")
    check("gate sites" in out, "gate sites line present")
    check("tainted by" in out, "tainted-by line present")
    check("flows through" in out, "flow-through helper line present")
    check("licensed side" in out, "licensed side line present")
    check("force value" in out, "force value line present")
    check("preview only" in out, "preview-only footer present")


def test_render_plan_empty():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = gates_mod.render_plan("EMPTY", [])
    out = buf.getvalue()
    check(ok is False, "render_plan returns False without candidates")
    check("no source-tainted, gate-only condition isolated" in out, "empty plan prints standard line")


def test_significance_clamps():
    check(gates_mod.significance(10, 100) == 0.1, "10/100 = 0.1")
    check(gates_mod.significance(-5, 100) == 0.0, "negative clamps to 0")
    check(gates_mod.significance(200, 100) == 1.0, "over-100% clamps to 1")
    check(gates_mod.significance(5, 0) == 1.0, "div by zero -> total=1, 5/1 -> clamp to 1")


def test_pick_licensed_tie_goes_to_a():
    # Implementation: returns a if score_a >= score_b.
    side, margin = gates_mod.pick_licensed(5.0, "A", 5.0, "B")
    check(side == "A" and margin == 0.0, "tie picks first (A) with 0 margin")
    side, margin = gates_mod.pick_licensed(3.0, "A", 7.0, "B")
    check(side == "B" and margin == 4.0, "higher score wins")


def main():
    fns = [test_bounded_solver_recovers_constant, test_emit_refuses_when_no_force_const,
           test_render_plan_outputs_expected_lines, test_render_plan_empty,
           test_significance_clamps, test_pick_licensed_tie_goes_to_a]
    for fn in fns:
        print("\n--", fn.__name__); fn()
    if FAILS:
        print("\nSOLVER/EMIT: %d failure(s)" % len(FAILS))
        for f in FAILS: print("  -", f)
        return 1
    print("\nSOLVER/EMIT: all OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
