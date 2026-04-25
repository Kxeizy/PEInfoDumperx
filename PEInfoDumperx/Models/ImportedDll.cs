using System.Collections.Generic;

namespace PEInfoDumperx.Models
{
    public class ImportedDll
    {
        public string DllName { get; set; } = string.Empty;

        // List of functions imported from this specific DLL
        public List<string> Functions { get; set; } = new List<string>();
    }
}