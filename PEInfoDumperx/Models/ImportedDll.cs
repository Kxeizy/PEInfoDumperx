using System.Collections.Generic;

namespace PEInfoDumperx.Models
{
    public class ImportedDll
    {
        public string DllName { get; set; } = string.Empty;
        public List<string> Functions { get; set; } = new();
    }
}
