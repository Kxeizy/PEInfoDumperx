# PE Info Dumper

A simple command-line tool written in C# that displays key information
from Windows Portable Executable (PE) files.

## 📌 Features

- Detects architecture (x86, x64, ARM64)
- Shows entry point RVA
- Displays compilation timestamp
- Identifies subsystem (GUI, Console, Native)
- Lists section names and virtual addresses

## 🚀 Usage

1. Download the latest release or compile from source.
2. Drag and drop any `.exe` file onto `PEInfoDumperx.exe`, or run from command line:

```bash
   PEInfoDumperx.exe C:\Windows\System32\notepad.exe
```

## 🛠️ Built With

- C# (.NET 9)
- `System.Reflection.PortableExecutable`

## 📚 Educational Purpose

This tool was developed as a learning project to understand the structure
of Windows executables. It is intended for **educational and research purposes only**.

## 👤 Author

- GitHub: [@Kxeizy](https://github.com/Kxeizy)
- Discord: `c0ffing`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
