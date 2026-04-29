using System;
using System.Collections.Generic;

namespace PEInfoDumperx.Models
{
    public class PEFileInfo
    {
        public string FileName { get; set; } = string.Empty;
        public string Architecture { get; set; } = string.Empty;
        public uint EntryPointRva { get; set; }
        public DateTime CompilationDate { get; set; }
        public string Subsystem { get; set; } = string.Empty;
        public bool IsPotentiallyPacked { get; set; }
        public bool IsDotNet { get; set; }

        public List<PESection> Sections { get; set; } = new();
        public List<ImportedDll> ImportedDlls { get; set; } = new();
        public List<string> ExportedFunctions { get; set; } = new();
        public List<string> Strings { get; set; } = new();
    }
}
