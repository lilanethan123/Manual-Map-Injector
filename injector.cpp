#include "injector.h"

#if defined(DISABLE_OUTPUT)
#define ILog(data, ...)
#else
#define ILog(text, ...) printf(text, __VA_ARGS__);
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)

static void AntiDebugEvasion() {
    DWORD start = GetTickCount();
    Sleep(rand() % 50 + 30);
    if (GetTickCount() - start < 15) {
        while (1) __nop();
    }
    
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) {
        pPeb->BeingDebugged = 0;
    }
#endif
}

static void ProcessDelayImports(BYTE* pBase, IMAGE_OPTIONAL_HEADER* pOpt, 
                                f_LoadLibraryA _LoadLibraryA, 
                                f_GetProcAddress _GetProcAddress) {
    IMAGE_DATA_DIRECTORY delayDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!delayDir.Size) return;
    
    auto* pDelayDescr = reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR*>(pBase + delayDir.VirtualAddress);
    
    while (pDelayDescr->DllNameRVA) {
        char* szMod = reinterpret_cast<char*>(pBase + pDelayDescr->DllNameRVA);
        HINSTANCE hDll = _LoadLibraryA(szMod);
        
        PIMAGE_THUNK_DATA pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pDelayDescr->ImportAddressTableRVA);
        PIMAGE_THUNK_DATA pINT = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pDelayDescr->ImportNameTableRVA);
        
        while (pINT->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal)) {
                pIAT->u1.Function = (ULONG_PTR)_GetProcAddress(hDll, 
                    reinterpret_cast<char*>(pINT->u1.Ordinal & 0xFFFF));
            } else {
                auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pINT->u1.AddressOfData);
                pIAT->u1.Function = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
            }
            ++pIAT;
            ++pINT;
        }
        ++pDelayDescr;
    }
}

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) {
        pData->hMod = (HINSTANCE)0x404040;
        return;
    }

    if (pData->AntiDebug) {
        AntiDebugEvasion();
    }

    BYTE* pBase = pData->pBase;
    auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
    auto* pOpt = &pNt->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta) {
        IMAGE_DATA_DIRECTORY relocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size) {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + relocDir.VirtualAddress);
            auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<BYTE*>(pRelocData) + relocDir.Size);
            
            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                UINT entries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                for (UINT i = 0; i < entries; ++i, ++pRelativeInfo) {
                    if (RELOC_FLAG(*pRelativeInfo)) {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(
                            pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    IMAGE_DATA_DIRECTORY importDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size) {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + importDir.VirtualAddress);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if (!pImportDescr->OriginalFirstThunk) {
                pThunkRef = pFuncRef;
            }

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, 
                        reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                } else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    ProcessDelayImports(pBase, pOpt, _LoadLibraryA, _GetProcAddress);

    IMAGE_DATA_DIRECTORY tlsDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + tlsDir.VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    bool ExceptionSupportFailed = false;

#ifdef _WIN64
    if (pData->SEHSupport) {
        IMAGE_DATA_DIRECTORY exceptDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exceptDir.Size) {
            if (!_RtlAddFunctionTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + exceptDir.VirtualAddress),
                exceptDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), 
                (DWORD64)pBase)) {
                ExceptionSupportFailed = true;
            }
        }
    }
#endif

    __try {
        _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);
        pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        pData->hMod = (HINSTANCE)0x606060;
        return;
    }

    if (ExceptionSupportFailed) {
        pData->hMod = (HINSTANCE)0x505050;
    }
}

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, 
                  bool ClearHeader, bool ClearNonNeededSections, 
                  bool AdjustProtections, bool SEHExceptionSupport, 
                  DWORD fdwReason, LPVOID lpReserved, 
                  DWORD TimeoutMs, bool AntiDebug) {
    
    auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        ILog("[-] Invalid DOS signature\n");
        return false;
    }

    auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        ILog("[-] Invalid NT signature\n");
        return false;
    }

    auto* pOpt = &pNt->OptionalHeader;
    auto* pFile = &pNt->FileHeader;

    if (pFile->Machine != CURRENT_ARCH) {
        ILog("[-] Architecture mismatch\n");
        return false;
    }

    ILog("[+] PE file validated\n");

    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, 
        pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        ILog("[-] Memory allocation failed: 0x%X\n", GetLastError());
        return false;
    }
    ILog("[+] Allocated memory at: %p\n", pTargetBase);

    DWORD headerSize = pOpt->SizeOfHeaders;
    if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, headerSize, nullptr)) {
        ILog("[-] Failed to write headers: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }
    ILog("[+] Headers written (%d bytes)\n", headerSize);

    IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNt);
    for (UINT i = 0; i < pFile->NumberOfSections; ++i, ++pSection) {
        if (pSection->SizeOfRawData) {
            if (!WriteProcessMemory(hProc, 
                pTargetBase + pSection->VirtualAddress,
                pSrcData + pSection->PointerToRawData,
                pSection->SizeOfRawData, nullptr)) {
                ILog("[-] Failed to write section %s: 0x%X\n", 
                    pSection->Name, GetLastError());
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
            ILog("[+] Section %s written\n", pSection->Name);
        }
    }

    MANUAL_MAPPING_DATA data = { 0 };
    data.pBase = pTargetBase;
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
    SEHExceptionSupport = false;
#endif
    data.fdwReasonParam = fdwReason;
    data.reservedParam = lpReserved;
    data.SEHSupport = SEHExceptionSupport;
    data.AntiDebug = AntiDebug;
    data.TimeoutMs = TimeoutMs;
    data.hMod = nullptr;

    BYTE* pMappingData = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, 
        sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pMappingData) {
        ILog("[-] Failed to allocate mapping data: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pMappingData, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        ILog("[-] Failed to write mapping data: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
        return false;
    }
    ILog("[+] Mapping data written at: %p\n", pMappingData);

    void* pShellcode = VirtualAllocEx(hProc, nullptr, ShellcodeSize, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        ILog("[-] Failed to allocate shellcode: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pShellcode, Shellcode, ShellcodeSize, nullptr)) {
        ILog("[-] Failed to write shellcode: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    ILog("[+] Shellcode written at: %p (%d bytes)\n", pShellcode, ShellcodeSize);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, 
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pMappingData, 0, nullptr);
    if (!hThread) {
        ILog("[-] CreateRemoteThread failed: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);
    ILog("[+] Remote thread executed\n");

    HINSTANCE hCheck = nullptr;
    DWORD startTime = GetTickCount();

    while (!hCheck) {
        DWORD exitCode = 0;
        GetExitCodeProcess(hProc, &exitCode);
        if (exitCode != STILL_ACTIVE) {
            ILog("[-] Target process crashed\n");
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }

        MANUAL_MAPPING_DATA dataCheck = { 0 };
        ReadProcessMemory(hProc, pMappingData, &dataCheck, sizeof(dataCheck), nullptr);
        hCheck = dataCheck.hMod;

        if (hCheck == (HINSTANCE)0x404040) {
            ILog("[-] Shellcode received invalid parameters\n");
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        else if (hCheck == (HINSTANCE)0x505050) {
            ILog("[!] SEH support failed - continuing anyway\n");
            break;
        }
        else if (hCheck == (HINSTANCE)0x606060) {
            ILog("[-] DllMain threw an exception\n");
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }

        if (GetTickCount() - startTime > TimeoutMs) {
            ILog("[-] Timeout waiting for DLL initialization\n");
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }

        Sleep(10);
    }

    ILog("[+] DLL mapped successfully at: %p\n", hCheck);

    BYTE* pEmptyBuffer = static_cast<BYTE*>(calloc(1, 20 * 1024 * 1024));
    if (pEmptyBuffer) {
        if (ClearHeader) {
            WriteProcessMemory(hProc, pTargetBase, pEmptyBuffer, headerSize, nullptr);
            ILog("[+] PE header wiped\n");
        }

        if (ClearNonNeededSections) {
            pSection = IMAGE_FIRST_SECTION(pNt);
            for (UINT i = 0; i < pFile->NumberOfSections; ++i, ++pSection) {
                if (pSection->Misc.VirtualSize) {
                    const char* name = reinterpret_cast<const char*>(pSection->Name);
                    if (strcmp(name, ".pdata") == 0 ||
                        strcmp(name, ".rsrc") == 0 ||
                        strcmp(name, ".reloc") == 0 ||
                        strcmp(name, ".idata") == 0) {
                        WriteProcessMemory(hProc, 
                            pTargetBase + pSection->VirtualAddress,
                            pEmptyBuffer, pSection->Misc.VirtualSize, nullptr);
                        ILog("[+] Cleared section: %s\n", name);
                    }
                }
            }
        }

        WriteProcessMemory(hProc, pShellcode, pEmptyBuffer, ShellcodeSize, nullptr);
        WriteProcessMemory(hProc, pMappingData, pEmptyBuffer, sizeof(MANUAL_MAPPING_DATA), nullptr);
        free(pEmptyBuffer);
    }

    if (AdjustProtections) {
        pSection = IMAGE_FIRST_SECTION(pNt);
        for (UINT i = 0; i < pFile->NumberOfSections; ++i, ++pSection) {
            if (pSection->Misc.VirtualSize) {
                DWORD newProtect = PAGE_READONLY;
                DWORD oldProtect = 0;

                if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    newProtect = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) 
                        ? PAGE_EXECUTE_READWRITE 
                        : PAGE_EXECUTE_READ;
                }
                else if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    newProtect = PAGE_READWRITE;
                }

                VirtualProtectEx(hProc, 
                    pTargetBase + pSection->VirtualAddress,
                    pSection->Misc.VirtualSize, newProtect, &oldProtect);
                ILog("[+] Section %s protection set to 0x%lX\n", 
                    pSection->Name, newProtect);
            }
        }
    }

    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);

    ILog("[+] Manual map completed successfully\n");
    return true;
}
