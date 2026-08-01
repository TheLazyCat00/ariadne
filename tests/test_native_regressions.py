"""End-to-end native regression coverage for Ariadne.

These tests exercise the real angr-backed frontend against the owned native
fixtures. They specifically lock in fixes for:

  * solve preferring real outcome sinks over unrelated large-function targets,
  * env-var source recovery through a simple register-copy chain,
  * verification working with absolute binary paths, and
  * patch preserving executable mode on the patched output.

Run: python tests/test_native_regressions.py
"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from calltree_backends.native_angr import NativeAngrFrontend, load_calltree, outcome_sinks
except Exception as exc:  # pragma: no cover - skip cleanly when deps are absent
    NativeAngrFrontend = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


# printf/puts outcome strings almost always end in "\n". These fixtures pin the
# fix for the whitespace filter in outcome_sinks (which previously required
# strictly 0x20..0x7e and so discarded every newline-terminated win/lose string)
# and the win-only patch fallback (a win sink present, reject text not word-listed).
#
# Leading newlines matter: gcc rewrites printf("...\n") with a trailing-only
# newline into puts("..."), which stores the string *without* the newline and so
# would not reproduce the bug. A leading "\n" blocks that rewrite, keeping the
# newline in the stored literal -- exactly the shape real crackmes use
# ("\n[+] Access granted.\n").
_NEWLINE_OUTCOME_SRC = r'''
#include <stdio.h>
#include <string.h>
int main(void){
    char buf[128];
    if(!fgets(buf,sizeof buf,stdin)) return 1;
    buf[strcspn(buf,"\n")]=0;
    if(strcmp(buf,"OPENSESAME")==0){ printf("\n[+] Access granted.\n"); return 0; }
    printf("\n[-] Access denied.\n");
    return 1;
}
'''

_WIN_ONLY_SRC = r'''
#include <stdio.h>
#include <string.h>
int main(void){
    char buf[128];
    if(!fgets(buf,sizeof buf,stdin)) return 1;
    buf[strcspn(buf,"\n")]=0;
    /* Reject text is deliberately NOT in the lose word-list, so only a win sink
       ("Access granted.") is classified -> exercises the win-only branch. */
    if(strcmp(buf,"OPENSESAME")==0){ printf("\n[+] Access granted.\n"); return 0; }
    printf("\nHmm, that string does not open it.\n");
    return 1;
}
'''


@unittest.skipUnless(shutil.which("gcc"), "gcc is required for native fixture tests")
@unittest.skipUnless(NativeAngrFrontend is not None, f"native backend unavailable: {_IMPORT_ERROR}")
class NativeRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = cls._tmp.name
        cls.crackme_bin = os.path.join(cls.tmpdir, "crackme_native")
        cls.flag_bin = os.path.join(cls.tmpdir, "flag_native")
        subprocess.run(
            ["gcc", os.path.join(ROOT, "fixtures", "native_crackme", "crackme_native.c"), "-O0", "-g", "-o", cls.crackme_bin],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["gcc", os.path.join(ROOT, "fixtures", "native_flag", "flag_native.c"), "-O0", "-g", "-o", cls.flag_bin],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _capture(self, fn, *args, **kwargs):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rv = fn(*args, **kwargs)
        return rv, buf.getvalue()

    def _compile(self, src, name):
        path = os.path.join(self.tmpdir, name)
        srcf = path + ".c"
        with open(srcf, "w") as f:
            f.write(src)
        subprocess.run(["gcc", srcf, "-O0", "-g", "-o", path],
                       check=True, capture_output=True, text=True)
        return path

    def test_outcome_sinks_recovers_newline_terminated_strings(self):
        """Win/lose strings ending in '\\n' must still be classified and anchored
        to their referencing blocks; the strict-printable filter used to drop them."""
        binp = self._compile(_NEWLINE_OUTCOME_SRC, "newline_outcome")
        proj, cfg = load_calltree(binp)
        win, lose, seen = outcome_sinks(proj, cfg)
        self.assertTrue(win, "newline-terminated win sink must be found")
        self.assertTrue(lose, "newline-terminated lose sink must be found")

    def test_patch_unlocks_with_newline_terminated_outcomes(self):
        binp = self._compile(_NEWLINE_OUTCOME_SRC, "newline_patch")
        fe = NativeAngrFrontend(binp)
        patched = binp + ".patched"
        rv, out = self._capture(fe.patch, patched)
        self.assertTrue(rv, out)
        ran = subprocess.run([patched], input=b"nope\n", capture_output=True,
                             timeout=6, cwd=self.tmpdir, check=False)
        self.assertIn(b"Access granted.", ran.stdout, out)

    def test_patch_win_only_when_reject_text_not_wordlisted(self):
        """A win sink with no classified lose sink should still be patchable via
        the win-oriented decision fallback."""
        binp = self._compile(_WIN_ONLY_SRC, "win_only")
        proj, cfg = load_calltree(binp)
        win, lose, seen = outcome_sinks(proj, cfg)
        self.assertTrue(win, "win sink expected")
        self.assertFalse(lose, "reject text should not be classified as a lose sink")
        fe = NativeAngrFrontend(binp)
        patched = binp + ".patched"
        rv, out = self._capture(fe.patch, patched)
        self.assertTrue(rv, out)
        ran = subprocess.run([patched], input=b"nope\n", capture_output=True,
                             timeout=6, cwd=self.tmpdir, check=False)
        self.assertIn(b"Access granted.", ran.stdout, out)

    def test_native_crackme_solve_finds_verified_key_from_absolute_path(self):
        fe = NativeAngrFrontend(self.crackme_bin)
        rv, out = self._capture(fe.solve)
        self.assertTrue(rv)
        self.assertIn("VERIFIED unlock", out)
        self.assertIn("NATIVE-KEY-9000", out)

    def test_native_flag_recovers_env_name_and_solves(self):
        fe = NativeAngrFrontend(self.flag_bin)
        self.assertIn("ARIADNE_LICENSE", fe.envs)
        rv, out = self._capture(fe.solve)
        self.assertTrue(rv)
        self.assertIn("VERIFIED unlock", out)
        self.assertIn("ARIADNE_LICENSE", out)
        self.assertIn("NATIVE-KEY-9000", out)

    def test_native_patch_preserves_executable_mode_and_unlocks(self):
        fe = NativeAngrFrontend(self.crackme_bin)
        patched = os.path.join(self.tmpdir, "crackme_native.patched")
        rv, out = self._capture(fe.patch, patched)
        self.assertTrue(rv)
        self.assertTrue(os.path.exists(patched), out)
        self.assertTrue(os.access(patched, os.X_OK), "patched binary must remain executable")
        ran = subprocess.run(
            [patched],
            input=b"wrong\n",
            capture_output=True,
            timeout=6,
            cwd=self.tmpdir,
            check=False,
        )
        self.assertEqual(ran.returncode, 0, ran.stdout.decode("latin1", "replace"))
        self.assertIn(b"License accepted. Welcome!", ran.stdout)


if __name__ == "__main__":
    unittest.main()
