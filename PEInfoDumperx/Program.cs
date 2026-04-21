using System;
using System.IO;
using System.Reflection.PortableExecutable;

namespace PEInfoDumper
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PEInfoDumper.exe <path to .exe file>");
                Console.WriteLine("Or drag and drop an .exe onto the executable.");
                return;
            }

            string filePath = args[0];

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"[ERROR] File '{filePath}' does not exist.");
                return;
            }

            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (PEReader peReader = new PEReader(fs))
                {
                    PEHeaders headers = peReader.PEHeaders;

                    // Verify that PE headers could be read
                    if (headers == null)
                    {
                        Console.WriteLine("[ERROR] Could not read PE headers. The file may not be a valid executable.");
                        return;
                    }

                    Console.WriteLine("=== PE INFO DUMPER ===");
                    Console.WriteLine($"File: {Path.GetFileName(filePath)}");
                    Console.WriteLine();

                    // Architecture
                    string architecture = headers.CoffHeader.Machine switch
                    {
                        Machine.I386 => "x86 (32-bit)",
                        Machine.Amd64 => "x64 (64-bit)",
                        Machine.Arm64 => "ARM64",
                        _ => headers.CoffHeader.Machine.ToString()
                    };
                    Console.WriteLine($"Architecture: {architecture}");

                    // Entry Point
                    int entryPointRva = headers.PEHeader.AddressOfEntryPoint;
                    Console.WriteLine($"Entry Point RVA: 0x{entryPointRva:X8}");

                    // Compilation timestamp
                    int timeStamp = headers.CoffHeader.TimeDateStamp;
                    DateTime compileTime = DateTime.UnixEpoch.AddSeconds(timeStamp);
                    Console.WriteLine($"Compilation Date: {compileTime.ToLocalTime()}");

                    // Subsystem
                    string subsystem = headers.PEHeader.Subsystem switch
                    {
                        Subsystem.WindowsGui => "Windows GUI",
                        Subsystem.WindowsCui => "Console",
                        Subsystem.Native => "Native",
                        _ => headers.PEHeader.Subsystem.ToString()
                    };
                    Console.WriteLine($"Subsystem: {subsystem}");

                    // Number of sections
                    Console.WriteLine($"Number of Sections: {headers.SectionHeaders.Length}");

                    // List sections
                    Console.WriteLine("\n--- SECTIONS ---");
                    foreach (SectionHeader section in headers.SectionHeaders)
                    {
                        Console.WriteLine($"  {section.Name.PadRight(8)} | VirtualSize: 0x{section.VirtualSize:X8} | VirtualAddress: 0x{section.VirtualAddress:X8}");
                    }

                    Console.WriteLine("\n--- IMPORTED DLLs ---");
                    Console.WriteLine("  (Feature under development)");
                }
            }
            catch (BadImageFormatException)
            {
                Console.WriteLine("[ERROR] The file is not a valid Windows executable (unrecognized PE format).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] {ex.Message}");
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}