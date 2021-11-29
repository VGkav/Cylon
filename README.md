# Cylon

This is a debug loader for 32bit Windows executables. It loads an executable with debugging privileges and monitors execution. All debug events are properly handled as transparently as possible. The ini file has three options for anti-debugging. The three methods are 

(1) Patching the PEB.Being.Debugged bit in memory

(2) Patching ZwQueryProcessInformation API

(3) Patching ZwSetInformationThread API

These may be unstable in newer Windows versions, only enable if needed.
