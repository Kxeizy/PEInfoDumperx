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
        private const double ENTROPY_THRESHOLD = 7.4;
        private const int MIN_STRING_LENGTH = 5;
        private const int ASCII_MIN = 32;
        private const int ASCII_MAX = 126;
        private const int EXPORT_TABLE_OFFSET = 24;
        private const ulong BIT_MASK_64 = 0x8000000000000000;
        private const uint BIT_MASK_32 = 0x80000000;
        private const uint RVA_MASK = 0x7FFFFFFF;

        public PEFileInfo Analyze(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File '{filePath}' not found.");

            var fileInfo = new PEFileInfo { FileName = Path.GetFileName(filePath) };
            byte[] fileBytes = File.ReadAllBytes(filePath);

            try
            {
                using (var ms = new MemoryStream(fileBytes))
                using (var peReader = new PEReader(ms))
                {
                    var headers = peReader.PEHeaders;
                    if (headers?.PEHeader == null)
                        throw new InvalidDataException("Invalid PE headers.");

                    PopulateBasicInfo(headers, fileInfo);
                    ParseSectionsAndEntropy(headers, fileBytes, fileInfo);
                    DetectPacker(fileInfo);
                    ParseImports(ms, headers, fileInfo);
                    ParseExports(ms, headers, fileInfo);
                    fileInfo.Strings = ExtractStrings(fileBytes);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to analyze PE file: {ex.Message}", ex);
            }

            return fileInfo;
        }

        private void PopulateBasicInfo(PEHeaders headers, PEFileInfo info)
        {
            info.Architecture = headers.CoffHeader.Machine.ToString();
            info.EntryPointRva = (uint)headers.PEHeader.AddressOfEntryPoint;
            info.CompilationDate = DateTime.UnixEpoch.AddSeconds(headers.CoffHeader.TimeDateStamp).ToLocalTime();
            info.Subsystem = headers.PEHeader.Subsystem.ToString();
            info.IsDotNet = headers.PEHeader.CorHeaderTableDirectory.Size > 0;
        }

        private void ParseSectionsAndEntropy(PEHeaders headers, byte[] fileBytes, PEFileInfo info)
        {
            foreach (var section in headers.SectionHeaders)
            {
                double entropy = 0;
                if (section.SizeOfRawData > 0)
                {
                    var sectionData = new byte[section.SizeOfRawData];
                    Array.Copy(fileBytes, section.PointerToRawData, sectionData, 0, section.SizeOfRawData);
                    entropy = CalculateShannonEntropy(sectionData);
                }

                info.Sections.Add(new PESection
                {
                    Name = section.Name.TrimEnd('\0'),
                    VirtualSize = (uint)section.VirtualSize,
                    VirtualAddress = (uint)section.VirtualAddress,
                    RawSize = (uint)section.SizeOfRawData,
                    Entropy = entropy
                });
            }
        }

        private void DetectPacker(PEFileInfo info)
        {
            foreach (var section in info.Sections)
            {
                if (section.Entropy > ENTROPY_THRESHOLD)
                    info.IsPotentiallyPacked = true;
                
                if (section.Name.Contains("UPX") || section.Name.Contains(".aspack"))
                    info.IsPotentiallyPacked = true;
            }
        }

        private List<string> ExtractStrings(byte[] data)
        {
            var results = new List<string>();
            var sb = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b >= ASCII_MIN && b <= ASCII_MAX)
                    sb.Append((char)b);
                else
                    AddStringIfValid(sb, results);
            }

            for (int i = 0; i < data.Length - 1; i += 2)
            {
                try
                {
                    ushort u = BitConverter.ToUInt16(data, i);
                    if (u >= ASCII_MIN && u <= ASCII_MAX)
                        sb.Append((char)u);
                    else
                        AddStringIfValid(sb, results);
                }
                catch { AddStringIfValid(sb, results); }
            }

            AddStringIfValid(sb, results);
            return results;
        }

        private void AddStringIfValid(StringBuilder sb, List<string> results)
        {
            if (sb.Length >= MIN_STRING_LENGTH)
                results.Add(sb.ToString());
            sb.Clear();
        }

        private double CalculateShannonEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;

            var counts = new int[256];
            foreach (byte b in data)
                counts[b]++;

            double entropy = 0;
            foreach (int count in counts)
            {
                if (count <= 0) continue;
                double p = (double)count / data.Length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private void ParseImports(Stream stream, PEHeaders headers, PEFileInfo info)
        {
            var dir = headers.PEHeader!.ImportTableDirectory;
            if (dir.Size <= 0) return;

            int offset = GetOffsetFromRva(dir.RelativeVirtualAddress, headers.SectionHeaders);
            if (offset <= 0) return;

            stream.Position = offset;
            using var reader = new BinaryReader(stream, Encoding.ASCII, true);

            while (true)
            {
                uint lookupRva = reader.ReadUInt32();
                reader.ReadUInt32();
                reader.ReadUInt32();
                uint nameRva = reader.ReadUInt32();
                uint iatRva = reader.ReadUInt32();

                if (lookupRva == 0 && nameRva == 0) break;

                long savedPos = stream.Position;
                int nameOffset = GetOffsetFromRva((int)nameRva, headers.SectionHeaders);
                
                if (nameOffset > 0)
                {
                    stream.Position = nameOffset;
                    var dll = new ImportedDll { DllName = ReadNullTerminatedString(stream) };
                    
                    uint tableRva = lookupRva != 0 ? lookupRva : iatRva;
                    int tableOffset = GetOffsetFromRva((int)tableRva, headers.SectionHeaders);
                    
                    if (tableOffset > 0)
                    {
                        stream.Position = tableOffset;
                        bool is64Bit = headers.PEHeader.Magic == PEMagic.PE32Plus;
                        ParseImportTable(stream, reader, headers, dll, is64Bit);
                    }
                    
                    info.ImportedDlls.Add(dll);
                }
                stream.Position = savedPos;
            }
        }

        private void ParseImportTable(Stream stream, BinaryReader reader, PEHeaders headers, ImportedDll dll, bool is64Bit)
        {
            while (true)
            {
                ulong value = is64Bit ? reader.ReadUInt64() : reader.ReadUInt32();
                if (value == 0) break;

                ulong mask = is64Bit ? BIT_MASK_64 : BIT_MASK_32;
                if ((value & mask) == 0)
                {
                    int funcOffset = GetOffsetFromRva((int)(value & RVA_MASK), headers.SectionHeaders);
                    if (funcOffset > 0)
                    {
                        long savedPos = stream.Position;
                        stream.Position = funcOffset + 2;
                        dll.Functions.Add(ReadNullTerminatedString(stream));
                        stream.Position = savedPos;
                    }
                }
            }
        }

        private void ParseExports(Stream stream, PEHeaders headers, PEFileInfo info)
        {
            var dir = headers.PEHeader!.ExportTableDirectory;
            if (dir.Size <= 0) return;

            int offset = GetOffsetFromRva(dir.RelativeVirtualAddress, headers.SectionHeaders);
            if (offset <= 0) return;

            stream.Position = offset + EXPORT_TABLE_OFFSET;
            using var reader = new BinaryReader(stream, Encoding.ASCII, true);

            uint numFunctions = reader.ReadUInt32();
            reader.ReadUInt32();
            uint namesRva = reader.ReadUInt32();

            int namesOffset = GetOffsetFromRva((int)namesRva, headers.SectionHeaders);
            if (namesOffset > 0)
            {
                stream.Position = namesOffset;
                var rvas = new uint[numFunctions];
                for (int i = 0; i < numFunctions; i++)
                    rvas[i] = reader.ReadUInt32();

                foreach (uint rva in rvas)
                {
                    int funcOffset = GetOffsetFromRva((int)rva, headers.SectionHeaders);
                    if (funcOffset > 0)
                    {
                        stream.Position = funcOffset;
                        info.ExportedFunctions.Add(ReadNullTerminatedString(stream));
                    }
                }
            }
        }

        private int GetOffsetFromRva(int rva, ImmutableArray<SectionHeader> sections)
        {
            foreach (var section in sections)
            {
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                    return section.PointerToRawData + (rva - section.VirtualAddress);
            }
            return -1;
        }

        private string ReadNullTerminatedString(Stream stream)
        {
            var bytes = new List<byte>();
            int b;
            while ((b = stream.ReadByte()) > 0)
                bytes.Add((byte)b);
            return Encoding.ASCII.GetString(bytes.ToArray());
        }
    }
}
