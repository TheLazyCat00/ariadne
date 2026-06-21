using System;

// Tiny license-gate crackme used to exercise the .NET IL frontend:
//   * Console.ReadLine  -> a recognized input SOURCE
//   * String ==         -> a recognized COMPARE against an ldstr constant
//   * Console.WriteLine -> a recognized SINK with win/lose outcome strings
//   * CheckLicense      -> a bool method whose return drives the gate
// The secret constant below is what the bounded solver / candidate extraction
// should surface from the IL.
class Program
{
    const string ExpectedKey = "ARIADNE-7F3A-2025";

    static bool CheckLicense(string key)
    {
        if (key == ExpectedKey)
        {
            Console.WriteLine("License accepted. Welcome!");
            return true;
        }
        Console.WriteLine("License invalid. Access denied.");
        return false;
    }

    static int Main(string[] args)
    {
        Console.Write("Enter license key: ");
        string key = Console.ReadLine();
        if (CheckLicense(key))
        {
            Console.WriteLine("Product unlocked.");
            return 0;
        }
        return 1;
    }
}
