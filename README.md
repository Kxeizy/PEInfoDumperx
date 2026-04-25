# PEInfoDumperx | X-Edition

![PEInfoDumperx Interface](assets/preview.png)

A simple and clean GUI tool to analyze Windows Portable Executables (PE). Built with a custom dark theme, it allows you to quickly extract and inspect information from `.exe`, `.dll`, and `.sys` files.

## 📌 Features

* **Drag & Drop:** Just drop a file into the window to analyze it.
* **Basic Info:** Reads architecture (x86, x64, ARM64), Entry Point, and subsystem.
* **Sections & Entropy:** Lists file sections (Virtual/Raw Size) and calculates entropy to detect if a file might be packed (flags in red if > 7.4).
* **Imports & Exports:** Shows a clean list of imported DLLs (IAT) and exported functions (EAT).
* **Strings Search:** Extracts readable strings from the binary and lets you filter them in real-time.

## 🚀 How to use

1. Download the latest release or compile the code with Visual Studio.
2. Run `PEInfoDumperx.exe`.
3. Drag and drop any PE file into the dashboard or click the **LOAD FILE** button.

## 🛠️ Built With

* C# (.NET 10.0 Windows)
* Custom Windows Forms UI
* `System.Reflection.PortableExecutable`

## 📚 Educational Purpose

This tool was created as a learning project to understand the internal structure of Windows executables. It is intended for educational purposes only.

## 👤 Author

* **GitHub:** [@Kxeizy](https://github.com/Kxeizy)
* **Discord:** c0ffing

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.