namespace PEInfoDumperx.Models
{
    public class PESection
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualSize { get; set; }
        public uint VirtualAddress { get; set; }
        public uint RawSize { get; set; }
        public double Entropy { get; set; }

        public double CompressionRatio => VirtualSize > 0 ? (double)RawSize / VirtualSize : 0;
    }
}
