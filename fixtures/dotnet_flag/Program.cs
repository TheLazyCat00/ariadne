using System;

// License-gate crackme variant for testing overload-aware patch discrimination
// in the .NET IL frontend. The gate boolean is `isLocked`, and every gate
// branch is written as Flip(isLocked) -- so the solver must recognize that the
// bool overload Flip(bool) participates in gatekeeping. Flip is ALSO overloaded
// for int (Flip(3) == -3) and used in a non-gating arithmetic context, so the
// solver must NOT conclude Flip is a gate-only helper and blanket-patch it.
//
//   * Environment.GetEnvironmentVariable -> external SOURCE (license state)
//   * String !=                          -> compare producing the gate bool
//   * isLocked                           -> one bool gating MULTIPLE branches
//   * Flip(bool) / Flip(int)             -> overloaded: gate use vs arithmetic
//   * Console.WriteLine                  -> recognized SINK / outcome strings
//
// Research note: the next analysis step finds the branches that gatekeep on the
// same expression (Flip(isLocked)), confirms isLocked is tainted by an external
// source, and patches only the bool sub-expression shared across those branches.
// The int overload of Flip below is the trap: a name-only patcher would corrupt
// it; a type/taint-aware patcher leaves it untouched.
class Program
{
    const string ExpectedKey = "ARIADNE-7F3A-2025";

    // flip(false) == true, flip(true) == false -- the bool / gate overload.
    static bool Flip(bool b) => !b;
    // flip(3) == -3 -- the int / arithmetic overload, never a gate.
    static int Flip(int n) => -n;

    static int Main(string[] args)
    {
        // External license state: an env var here, but it could equally be a
        // file or registry value -- all are recognized sources.
        string license = Environment.GetEnvironmentVariable("ARIADNE_LICENSE");
        bool isLocked = license != ExpectedKey;

        // Every gate branch goes through Flip(isLocked): true means unlocked.
        if (Flip(isLocked))
            Console.WriteLine("License accepted. Welcome!");
        else
            Console.WriteLine("License invalid. Access denied.");

        if (Flip(isLocked))
            Console.WriteLine("Premium features unlocked.");

        // Non-gating use of the SAME Flip name on an int. Pure arithmetic; the
        // solver must leave this alone even though Flip(bool) drives the gate.
        int balance = 3;
        Console.WriteLine("flip(3) = " + Flip(balance));

        return Flip(isLocked) ? 0 : 1;
    }
}
