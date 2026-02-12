#include "injector.h"
#include <stdio.h>
#include <string>
#include <iostream>
#include <chrono>
#include <thread>

using namespace std;

bool IsCorrectTargetArchitecture(HANDLE hProc) {
    BOOL bTarget = FALSE;
    if (!IsWow64Process(hProc, &bTarget)) {
        printf("[-] Failed to query target architecture: 0x%X\n", GetLastError());
        return false;
    }

    BOOL bHost = FALSE;
    IsWow64Process(GetCurrentProcess(), &bHost);
    
    bool archMatch = (bTarget == bHost);
    printf("[+] Target architecture: %s\n", bTarget ? "x86" : "x64");
    printf("[+] Host architecture: %s\n", bHost ? "x86" : "x64");
    
    return archMatch;
}

DWORD GetProcessIdByName(const wchar_t* name) {
    PROCESSENTRY32 entry = { 0 };
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot: 0x%X\n", GetLastError());
        return 0;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES tp = { 0 };
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token: 0x%X\n", GetLastError());
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        printf("[-] Failed to lookup privilege: 0x%X\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        printf("[-] Failed to adjust token privileges: 0x%X\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    
    CloseHandle(hToken);
    printf("[+] Debug privilege enabled\n");
    return true;
}

bool WaitForProcess(const wchar_t* processName, DWORD& pid, DWORD timeoutMs = 30000) {
    auto start = chrono::steady_clock::now();
    
    while (true) {
        pid = GetProcessIdByName(processName);
        if (pid != 0) {
            printf("[+] Found process: %ls (PID: %d)\n", processName, pid);
            return true;
        }
        
        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - start).count();
        
        if (elapsed > timeoutMs) {
            printf("[-] Timeout waiting for process: %ls\n", processName);
            return false;
        }
        
        this_thread::sleep_for(chrono::milliseconds(100));
    }
}

bool ReadDllFile(const wchar_t* dllPath, BYTE*& pSrcData, SIZE_T& fileSize) {
    ifstream file(dllPath, ios::binary | ios::ate);
    if (!file.is_open()) {
        printf("[-] Failed to open DLL file: %ls\n", dllPath);
        return false;
    }
    
    fileSize = file.tellg();
    if (fileSize < 0x1000) {
        printf("[-] Invalid DLL file size: %zu bytes\n", fileSize);
        file.close();
        return false;
    }
    
    pSrcData = new BYTE[fileSize];
    if (!pSrcData) {
        printf("[-] Failed to allocate memory for DLL data\n");
        file.close();
        return false;
    }
    
    file.seekg(0, ios::beg);
    file.read(reinterpret_cast<char*>(pSrcData), fileSize);
    file.close();
    
    printf("[+] DLL loaded: %ls (%zu bytes)\n", dllPath, fileSize);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    printf("=== Manual Map Injector ===\n\n");
    
    wchar_t* dllPath = nullptr;
    wchar_t* processName = nullptr;
    DWORD pid = 0;
    
    if (argc == 3) {
        dllPath = argv[1];
        processName = argv[2];
        printf("[+] Command line: %ls -> %ls\n", dllPath, processName);
    }
    else if (argc == 2) {
        dllPath = argv[1];
        printf("[+] DLL: %ls\n", dllPath);
        
        string input;
        printf("[?] Enter target process name: ");
        getline(cin, input);
        
        size_t len = input.length() + 1;
        processName = new wchar_t[len];
        mbstowcs_s(nullptr, processName, len, input.c_str(), len - 1);
    }
    else {
        printf("[-] Invalid parameters\n");
        printf("[*] Usage: %ls <dll_path> [process_name]\n", argv[0]);
        system("pause");
        return 1;
    }
    
    EnableDebugPrivilege();
    
    printf("[*] Waiting for process: %ls\n", processName);
    if (!WaitForProcess(processName, pid)) {
        printf("[-] Process not found: %ls\n", processName);
        delete[] processName;
        system("pause");
        return 2;
    }
    
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: 0x%X\n", GetLastError());
        printf("[!] Run as Administrator\n");
        delete[] processName;
        system("pause");
        return 3;
    }
    printf("[+] Process handle opened (PID: %d)\n", pid);
    
    if (!IsCorrectTargetArchitecture(hProc)) {
        printf("[-] Architecture mismatch\n");
        CloseHandle(hProc);
        delete[] processName;
        system("pause");
        return 4;
    }
    
    BYTE* pSrcData = nullptr;
    SIZE_T fileSize = 0;
    if (!ReadDllFile(dllPath, pSrcData, fileSize)) {
        CloseHandle(hProc);
        delete[] processName;
        system("pause");
        return 5;
    }
    
    printf("[*] Mapping DLL...\n");
    bool success = ManualMapDll(
        hProc, pSrcData, fileSize,
        true, true, true, true,
        DLL_PROCESS_ATTACH, nullptr, 5000, true
    );
    
    delete[] pSrcData;
    CloseHandle(hProc);
    
    if (success) {
        printf("[+] SUCCESS: DLL manually mapped\n");
    } else {
        printf("[-] Manual map failed\n");
        delete[] processName;
        system("pause");
        return 6;
    }
    
    delete[] processName;
    printf("\n[+] Done\n");
    system("pause");
    return 0;
}
