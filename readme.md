# Manual Map Injector

A production-grade, feature-complete manual mapping DLL injector for Windows x64. Loads DLLs into target processes without using `LoadLibrary`, leaving no PE header or module entry in the PEB.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Windows](https://img.shields.io/badge/Windows-10|11-blue)
![x64](https://img.shields.io/badge/Arch-x64-blue)

---

## ✨ Features

| Feature | Status |
|---------|--------|
| ✅ **Full PE Parsing** | DOS/NT headers, sections, directories |
| ✅ **Relocation Fixup** | x86/x64 delta calculation, all types |
| ✅ **Import Resolution** | Ordinal + named imports |
| ✅ **Delay-Load Imports** | Full support |
| ✅ **TLS Callbacks** | Executes before DllMain |
| ✅ **x64 SEH Support** | `RtlAddFunctionTable` registration |
| ✅ **Anti-Debug** | Timing attacks, PEB corruption |
| ✅ **Header Wiping** | Erases `MZ`/`PE` signatures post-load |
| ✅ **Section Wiping** | `.pdata`, `.reloc`, `.rsrc`, `.idata` |
| ✅ **Memory Protection** | Sets correct `PAGE_*` flags per section |
| ✅ **Timeout Protection** | Configurable wait for DllMain |
| ✅ **Arch Validation** | Prevents 32/64-bit mismatches |
| ✅ **Debug Privilege** | Auto-elevation via `SeDebugPrivilege` |
| ✅ **Process Waiting** | Waits for target to launch |
| ✅ **Cleanup** | Zero memory leaks, all paths freed |

---

## 🎯 Compatibility

| Target | Works |
|--------|--------|
| ✅ **Any x64 DLL** | Any valid PE32+ DLL |
| ✅ **Any x64 Process** | Games, tools, system processes (Admin) |
| ✅ **DirectX 9/10/11 Hooks** | ImGui, Kiero, MinHook |
| ✅ **No Anti-Cheat** | Fully functional |
| ⚠️ **EAC/BattlEye** | Requires kernel bypass (out of scope) |

---


Manual-Map-Injector/
├── injector.h # Structures, prototypes, exports
├── injector.cpp # Core manual mapping logic + shellcode
├── main.cpp # Injector UI, process handling, DLL loading
├── shellcode.asm # x64 assembly stub (calls Shellcode())
├── shellcode.h # GENERATED - raw shellcode bytes
├── generate_shellcode.bat # Builds shellcode.asm → shellcode.h
├── gen_shellcode.py # Converts .obj rawdata to C array
└── README.md # You are here



---

## 🔧 Building the Injector

### Prerequisites

- **Visual Studio 2019/2022** with:
  - Desktop development with C++
  - x64 build tools
- **Python 3.x** (for shellcode generation)
- **Windows SDK** (included with VS)

### Step 1: Generate Shellcode

```batch
# Open "x64 Native Tools Command Prompt for VS"
cd \path\to\project
generate_shellcode.bat



## 📁 Project Structure
