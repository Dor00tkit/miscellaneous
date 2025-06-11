# **PPL Helper**

A [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) [JavaScript](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/javascript-debugger-scripting) extension to list and disable [[Protected Process Light](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#introduction)] (PPL) protection on Windows processes.

## **Usage**

1. Load the script in WinDbg:
   ```
   .scriptload "C:\path\to\ppl.js"
   ```

2. Available commands:
   - `!list_ppl` - List all PPL protected processes
   - `!disable_ppl "process.exe"` - Disable PPL for specific process by name
   - `!disable_ppl 0x100` - Disable PPL for specific process by PID
   - `!disable_all_ppl` - Disable PPL for all protected processes

**You must update the `EPROCESS_SIGNATURELEVEL_OFFSET` value in the script to match your target OS version.**

The current offset `0x5f8` is for Windows 11 24H2 x64. Check [Vergilius Project](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS) or use `dt nt!_EPROCESS` in WinDbg to find the correct offset for your system.