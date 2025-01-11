# AMSIReaper

AMSIReaper is a project focused on exploring memory manipulation, process injection, and the use of the Export Address Table (EAT) for targeting specific functions in remote processes. This project demonstrates key concepts in advanced memory handling by injecting a patch into the `AmsiOpenSession` function of `amsi.dll` loaded in a target process.

---

## Overview

This project manipulates the memory of a target process to achieve the following:

- Open and interact with another process's memory space using Windows APIs like `OpenProcess` and `WriteProcessMemory`.
- Locate specific modules (DLLs) within a remote process using `EnumProcessModules` and related functions.
- Parse the Export Address Table (EAT) of a remote module to locate specific functions by name.
- Write a patch to the identified function to alter its behavior.

### Key Concepts

1. **Memory Manipulation**: This involves reading and writing memory in a remote process.
2. **Export Address Table (EAT)**: A structure in PE (Portable Executable) files that provides the names and addresses of exported functions.
3. **Code Injection**: Writing data to the memory space of a running process to alter its behavior.

---

## Prerequisites

- A basic understanding of Windows system internals and process management.
- Knowledge of the Portable Executable (PE) file format.
- Familiarity with C++ programming and memory handling.

---

## Features

- **Process Access**: Opens the memory space of a target process using `OpenProcess` with appropriate permissions.
- **Module Enumeration**: Enumerates and identifies loaded modules (DLLs) in the target process.
- **Function Address Resolution**: Parses the Export Address Table to resolve the address of specific functions within a DLL.
- **Memory Writing**: Writes a single-byte patch to alter the behavior of the targeted function.

---

## Code Walkthrough

### 1. **Class: AMSIReaper**

#### Public Methods:

- `OpenProcess`: Opens a handle to the target process with specified access permissions.
- `WriteProcessMemory`: Writes data to the memory of the target process.
- `CloseHandle`: Closes the handle to the target process.
- `GetRemoteModuleHandle`: Enumerates modules in the target process and retrieves a handle to the specified module.
- `GetRemoteProcAddress`: Resolves the address of a function by parsing the Export Address Table of the module.

### 2. **Main Logic**

- The main function hardcodes the target process ID (`processId`) and the patch byte (`0xEB`).
- Opens the target process and retrieves a handle to `amsi.dll`.
- Locates the `AmsiOpenSession` function by parsing the Export Address Table of `amsi.dll`.
- Writes a single-byte patch to modify the behavior of `AmsiOpenSession`.

---

## Usage

### Steps to Run

1. **Set the Target Process ID**:
   Update the `processId` variable in the `main()` function with the PID of the target process.

2. **Compile the Code**:
   Use any C++ compiler with Windows SDK support to compile the code.
   ```
   g++ -o AMSIReaper AMSIReaper.cpp -lpsapi
   ```
   
3. **Execute the Binary**:
   Disable your antivirus then run the compiled binary as it is still getting dynamically detected.

### Example:

Assuming the target process has a PID of `9148`:

- Update the `processId` variable in the code:
  ```cpp
  DWORD processId = 9148;
  ```

- Compile and execute the binary.

- Observe the output:
  - If successful, the console will display:
    ```
    Memory patched successfully!
    ```
  - On failure, detailed error messages will be printed.

---

## Important Notes

1. **Hardcoded Values**:
   - The `processId` and patch offset are hardcoded and must be updated as needed.

2. **Error Handling**:
   - The code includes error messages to help debug issues like failing to locate a module or write memory.

3. **Safety**:
   - Running this program on unauthorized systems or processes may violate laws and security policies. Use only in controlled environments.

4. **Testing Environment**:
   - Always test in a virtual machine or sandbox to prevent unintended consequences.

---

## Technical Details

### Memory Manipulation
- The code uses `ReadProcessMemory` and `WriteProcessMemory` to read and modify the memory of a remote process.
- Proper alignment and offsets are calculated to ensure accurate memory access.

### Export Address Table (EAT)
- The Export Address Table of `amsi.dll` is parsed to locate the `AmsiOpenSession` function.
- Function names and RVAs are resolved by reading and interpreting the table in the remote process's memory space.

### Patch Details
- A single-byte patch (`0xEB`) is written to alter the flow of the `AmsiOpenSession` function. The exact offset within the function is hardcoded and may require adjustment for different builds of `amsi.dll`.

---

## Disclaimer

This project is intended solely for educational purposes. Misuse of this code to alter the behavior of processes without authorization is strictly prohibited and may result in legal consequences. Always use responsibly in environments where you have explicit permission.

---

## References

- [Windows API Documentation](https://learn.microsoft.com/en-us/windows/win32/api/)
- [Portable Executable File Format](https://en.wikipedia.org/wiki/Portable_Executable)
- [Psapi.h Documentation](https://learn.microsoft.com/en-us/windows/win32/psapi/psapi-functions)

