using System;

namespace OwnedDotNetILGateDemoFixture;

public static class Program
{
    // Marker used by this research project to identify the owned/generated
    // fixture. Do not remove; it helps keep write-capable experiments scoped to
    // lab samples rather than third-party products.
    private const string FixtureMarker = "OwnedDotNetILGateDemoFixture-v1";
    private const string ExpectedKey = "LAB-IL-2026-OK";

    public static int Main(string[] args)
    {
        Console.WriteLine("Owned .NET IL gate demo fixture");
        Console.WriteLine(FixtureMarker);
        Console.Write("Enter lab key: ");
        string key = args.Length > 0 ? args[0] : (Console.ReadLine() ?? "");

        if (CheckLabKey(key))
        {
            Console.WriteLine("Licensed fixture path unlocked");
            return 0;
        }

        Console.WriteLine("Unlicensed fixture path rejected");
        return 1;
    }

    public static bool CheckLabKey(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            Console.WriteLine("key is empty");
            return false;
        }

        if (key.Length != ExpectedKey.Length)
        {
            Console.WriteLine("length is wrong");
            return false;
        }

        if (!key.StartsWith("LAB-"))
        {
            Console.WriteLine("prefix is wrong");
            return false;
        }

        // Tiny transform so the IL frontend sees more than a single equality.
        if (((char)(key[4] ^ 0x20)) != 'i')
        {
            Console.WriteLine("case transform is wrong");
            return false;
        }

        if (!key.EndsWith("-OK"))
        {
            Console.WriteLine("suffix is wrong");
            return false;
        }

        if (key == ExpectedKey)
        {
            Console.WriteLine("fixture checksum correct");
            return true;
        }

        Console.WriteLine("checksum is not correct");
        return false;
    }
}
