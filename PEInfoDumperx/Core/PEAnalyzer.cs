using System;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Collections.Immutable;
using System.Collections.Generic;
using System.Text;
using PEInfoDumperx.Models;

namespace PEInfoDumperx.Core
{
    public class PEAnalyzer
    {
        public PEFileInfo Analyze(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File '{filePath}' not found.");

            var fileInfo = new PEFileInfo { FileName = Path.GetFileName(filePath) };
            byte[] allBytes = File.ReadAllBytes(filePath);

            using (MemoryStream ms = new MemoryStream(allBytes))
            using (PEReader peReader = new PEReader(ms))
            {
                PEHeaders headers = peReader.PEHeaders;
                if (headers == null || headers.PEHeader == null)
                    throw new InvalidDataException("Invalid PE headers.");

                fileInfo.Architecture = headers.CoffHeader.Machine.ToString();
                fileInfo.EntryPointRva = headers.PEHeader.AddressOfEntryPoint;
                fileInfo.CompilationDate = DateTime.UnixEpoch.AddSeconds(headers.CoffHeader.TimeDateStamp).ToLocalTime();
                fileInfo.Subsystem = headers.PEHeader.Subsystem.ToString();
                if (headers.PEHeader.CorHeaderTableDirectory.Size > 0) fileInfo.IsDotNet = true;

                // 1. Sections & Entropy
                foreach (SectionHeader section in headers.SectionHeaders)
                {
                    double sectionEntropy = 0;
                    if (section.SizeOfRawData > 0)
                    {
                        byte[] sectionData = new byte[section.SizeOfRawData];
                        Array.Copy(allBytes, section.PointerToRawData, sectionData, 0, section.SizeOfRawData);
                        sectionEntropy = CalculateShannonEntropy(sectionData);
                    }

                    fileInfo.Sections.Add(new PESection
                    {
                        Name = section.Name,
                        VirtualSize = section.VirtualSize,
                        VirtualAddress = section.VirtualAddress,
                        RawSize = section.SizeOfRawData,
                        Entropy = sectionEntropy
                    });
                }

                // 2. Packer Detection
                foreach (var sec in fileInfo.Sections)
                {
                    if (sec.Entropy > 7.4) fileInfo.IsPotentiallyPacked = true;
                    if (sec.Name.Contains("UPX") || sec.Name.Contains(".aspack")) fileInfo.IsPotentiallyPacked = true;
                }

                // 3. IAT & EAT
                ParseImports(ms, headers, fileInfo);
                ParseExports(ms, headers, fileInfo);

                // 4. Extract Strings (ASCII & Unicode)
                fileInfo.Strings = ExtractStrings(allBytes, 5);
            }

            return fileInfo;
        }

        private List<string> ExtractStrings(byte[] data, int minLength)
        {
            var results = new List<string>();

            // ASCII Scan
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b >= 32 && b <= 126) sb.Append((char)b);
                else
                {
                    if (sb.Length >= minLength) results.Add(sb.ToString());
                    sb.Clear();
                }
            }

            // Unicode (UTF-16LE) Scan
            for (int i = 0; i < data.Length - 1; i += 2)
            {
                ushort u = BitConverter.ToUInt16(data, i);
                if (u >= 32 && u <= 126) sb.Append((char)u);
                else
                {
                    if (sb.Length >= minLength) results.Add(sb.ToString());
                    sb.Clear();
                }
            }
            return results;
        }

        private double CalculateShannonEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            int[] counts = new int[256];
            foreach (byte b in data) counts[b]++;
            double entropy = 0;
            foreach (int count in counts)
            {
                if (count == 0) continue;
                double p = (double)count / data.Length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private void ParseImports(Stream s, PEHeaders h, PEFileInfo info)
        {
            var dir = h.PEHeader!.ImportTableDirectory;
            if (dir.Size <= 0) return;
            int offset = GetOffsetFromRva(dir.RelativeVirtualAddress, h.SectionHeaders);
            if (offset <= 0) return;
            s.Position = offset;
            using BinaryReader br = new BinaryReader(s, Encoding.ASCII, true);
            while (true)
            {
                uint lookupRva = br.ReadUInt32();
                br.ReadUInt32(); br.ReadUInt32();
                uint nameRva = br.ReadUInt32();
                uint iatRva = br.ReadUInt32();
                if (lookupRva == 0 && nameRva == 0) break;
                long pos = s.Position;
                int nOff = GetOffsetFromRva((int)nameRva, h.SectionHeaders);
                if (nOff > 0)
                {
                    s.Position = nOff;
                    var dll = new ImportedDll { DllName = ReadString(s) };
                    uint tRva = lookupRva != 0 ? lookupRva : iatRva;
                    int tOff = GetOffsetFromRva((int)tRva, h.SectionHeaders);
                    if (tOff > 0)
                    {
                        s.Position = tOff;
                        bool x64 = h.PEHeader.Magic == PEMagic.PE32Plus;
                        while (true)
                        {
                            ulong val = x64 ? br.ReadUInt64() : br.ReadUInt32();
                            if (val == 0) break;
                            if ((val & (x64 ? 0x8000000000000000 : 0x80000000)) == 0)
                            {
                                int fOff = GetOffsetFromRva((int)(val & 0x7FFFFFFF), h.SectionHeaders);
                                if (fOff > 0) { long p2 = s.Position; s.Position = fOff + 2; dll.Functions.Add(ReadString(s)); s.Position = p2; }
                            }
                        }
                    }
                    info.ImportedDlls.Add(dll);
                }
                s.Position = pos;
            }
        }

        private void ParseExports(Stream s, PEHeaders h, PEFileInfo info)
        {
            var dir = h.PEHeader!.ExportTableDirectory;
            if (dir.Size <= 0) return;
            int off = GetOffsetFromRva(dir.RelativeVirtualAddress, h.SectionHeaders);
            if (off <= 0) return;
            s.Position = off + 24;
            using BinaryReader br = new BinaryReader(s, Encoding.ASCII, true);
            uint num = br.ReadUInt32(); br.ReadUInt32(); uint namesRva = br.ReadUInt32();
            int nOff = GetOffsetFromRva((int)namesRva, h.SectionHeaders);
            if (nOff > 0)
            {
                s.Position = nOff;
                uint[] rvas = new uint[num];
                for (int i = 0; i < num; i++) rvas[i] = br.ReadUInt32();
                foreach (uint r in rvas)
                {
                    int sOff = GetOffsetFromRva((int)r, h.SectionHeaders);
                    if (sOff > 0) { s.Position = sOff; info.ExportedFunctions.Add(ReadString(s)); }
                }
            }
        }

        private int GetOffsetFromRva(int rva, ImmutableArray<SectionHeader> sections)
        {
            foreach (var s in sections) if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize) return s.PointerToRawData + (rva - s.VirtualAddress);
            return -1;
        }

        private string ReadString(Stream s)
        {
            var b = new List<byte>();
            int v; while ((v = s.ReadByte()) > 0) b.Add((byte)v);
            return Encoding.ASCII.GetString(b.ToArray());
        }
    }
}