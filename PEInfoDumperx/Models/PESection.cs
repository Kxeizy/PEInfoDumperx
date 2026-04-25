namespace PEInfoDumperx.Models
{
    public class PESection
    {
        public string Name { get; set; } = string.Empty;
        public int VirtualSize { get; set; }
        public int VirtualAddress { get; set; }
        public int RawSize { get; set; }
        public double Entropy { get; set; } 
    }
}