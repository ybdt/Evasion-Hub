using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Security.Principal;

namespace EDRChoker
{
    class Utils
    {
        public string[] procName;

        public void ReadCleanFile(string filePath)
        {
            try
            {
                procName = File.ReadLines(filePath)
                               .Select(line => line.Trim())
                               .Where(trimmedLine => !string.IsNullOrEmpty(trimmedLine))
                               .ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"File error: {ex.Message}");
                procName = Array.Empty<string>();
            }
        }
        public void ShowBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"  ___ ___  ___  ___ _  _  ___  _  _____ ___ ");
            Console.WriteLine(@" | __|   \| _ \/ __| |_| |/ _ \| |/ / __| _ \");
            Console.WriteLine(@" | _|| |) |   / (__|  _  | (_) | ' <| _||   /");
            Console.WriteLine(@" |___|___/|_|_\\___|_| |_|\___/|_|\_\___|_|_\");

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("\n  EDRChoker: You can pass, but just a little");

            // Made bright using ConsoleColor.White
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Two Seven One Three: x.com/TwoSevenOneT\n");

            Console.ResetColor();
        }

        public bool IsRunningAsAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
