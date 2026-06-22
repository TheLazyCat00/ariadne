using System;

// License-gate crackme variant that gates on a boolean *variable* (isUnlocked)
// instead of a CheckLicense() method, for exercising taint-based branch
// discovery in the .NET IL frontend:
//   * Environment.GetEnvironmentVariable -> external SOURCE (license state)
//   * String ==                          -> the compare producing the gate bool
//   * isUnlocked                         -> one bool that gates MULTIPLE branches
//   * Console.WriteLine                  -> recognized SINK / outcome strings
//
// Research note: the next analysis step does not look for a CheckLicense()
// method. It finds the branches that gatekeep on the same expression
// (isUnlocked), confirms that expression is tainted by an external source, and
// patches only the boolean sub-expression shared across those branches.
//
// The Flip overloads below are a deliberate decoy: Flip(bool) participates in
// the gate, but Flip(int) is ordinary arithmetic (Flip(3) == -3). A correct
// patch must touch only the bool-typed sub-expression, never the int overload.
class Program
{
    const string ExpectedKey = "ARIADNE-7F3A-2025";

    static bool Flip(bool b) => !b;
    static int Flip(int n) => -n;

    static int Main(string[] args)
    {
        // External license state: an env var here, but it could equally be a
        // file or registry value -- all are recognized sources.
        string license = Environment.GetEnvironmentVariable("ARIADNE_LICENSE");
        bool isUnlocked = license == ExpectedKey;

        // The same boolean variable gatekeeps several branches; none is a method
        // call -- the gate lives entirely in `isUnlocked`.
        if (isUnlocked)
            Console.WriteLine("License accepted. Welcome!");
        else
            Console.WriteLine("License invalid. Access denied.");

        // Flip(bool) is the bool overload, so this is still part of the gate.
        if (!Flip(isUnlocked))
            Console.WriteLine("Product unlocked.");

        // Flip(int) is the arithmetic overload; this expression must NOT be
        // patched even though it shares the Flip name with the gate above.
        int demo = Flip(3);
        Console.WriteLine("flip(3) = " + demo);

        return isUnlocked ? 0 : 1;
    }
}
