using System.Diagnostics.CodeAnalysis;

namespace AsymmetricCryptography;

public static class FileLogger
{
    public static void Log([StringSyntax("CompositeFormat")] String format, params object?[] args)
    {
        using (StreamWriter sw = File.AppendText("output.log"))
        {
            sw.WriteLine(string.Format(format, args));
        }
    }
}