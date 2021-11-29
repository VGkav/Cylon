; there is a structure loose, and the VPEx will need adjusting, if it's to be readded
; may want to use VPEx to reinstate the original security access (careful with tempdword)


    .586p
    .model flat, stdcall
    option casemap :none 

ASSUME  cs:FLAT, ds:FLAT, ss:FLAT, es:FLAT, fs:FLAT, gs:ERROR

    include \masm32\include\windows.inc
    include \masm32\include\masm32.inc
    include \masm32\include\user32.inc
    include \masm32\include\shell32.inc  
    include \masm32\include\shlwapi.inc  
    include \masm32\include\kernel32.inc
    include \masm32\include\comdlg32.inc
    include	\masm32\macros\macros.asm
    include  C:\masm32\work\Cylon\include\parser.inc
    include  C:\masm32\work\Cylon\parser.core.asm
    
    includelib \masm32\lib\masm32.lib
    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\shell32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\shlwapi.lib
    includelib \masm32\lib\comdlg32.lib   


EAX_ID equ 45001
EBX_ID equ 45002
ECX_ID equ 45003
EDX_ID equ 45004
EBP_ID equ 45005
ESP_ID equ 45006
EIP_ID equ 45007
ESI_ID equ 45008
EDI_ID equ 45009


PROCESS_BASIC_INFORMATION STRUCT
    Reserved1             PVOID  ?
    PebBaseAddress       DWORD  ?
    Reserved2          PVOID ?
    UniqueProcessId  ULONGLONG  ? 
    Reserved3             PVOID ? 
PROCESS_BASIC_INFORMATION  ENDS

    .data

ofn   OPENFILENAME <>
FilterString db "All Files",0,"*.*",0
             db "Executable Files",0,"*.exe",0,0
lpstrTitlestring db "Select file to run with debugging privileges",0

bufferzerobyte db 0
ProgTitle          db "Cylon  Debug  Loader",0
TargetExitedText   db "Target main thread has exited !",0
error_msg db  "An error has occured, closing down !" , 0
ntdll_string db "ntdll.dll",0
ntqip_string db "NtQueryInformationProcess",0
ntsit_string db "NtSetInformationThread",0
OptionsFileName db ".\Cylon.ini",0
Antiantidebuggingstring db "Anti-anti-debugging",0
PEBBDstring db "PEBBD",0
PEBBDoptionskip db 0
ZWQPIstring db "ZWQPI",0
ZWQPIoptionskip db 0
ZWSITstring db "ZWSIT",0
ZWSIToptionskip db 0
open_str db "open",0
exeinfope_string db "exeinfope.exe ",22h,0
exact_exeinfo_str db "exeinfope.exe",0
exeinfope_params db 2ah,22h," /s",0
epe_log_string db "!ExEinfo-Multiscan.log",0
zwqip_code_cave  db  0FFh, 12h, 83h, 7Ch, 24h, 08h, 07h, 75h, 0Ch, 8Bh, 44h, 24h, 0Ch, 0C7h, 00h, 00h, 00h, 00h, 00h, 33h, 0C0h, 0C2h, 14h, 00h  ; 18h bytes
zwsit_code_cave  db  83h, 7Ch, 24h, 08h, 11h, 75h, 03h,  0C2h, 10h, 00h, 0B8h, 0E5h, 00h, 00h, 00h, 0h, 0h, 0h   ; 12h bytes
newline db 13,10,0


.data?

newdir dd ?
hInstance dd ?
startinfo STARTUPINFO <>
pi PROCESS_INFORMATION <>
FNamePtr dd ?
NTDLLbase dd ?
ntqip_address dd ?
tempdword dd ?
realdir db 128 dup(?)
targetdir db 128 dup(?)
namebuffer db 128 dup(?)
buffer db 512 dup(?)
pbi PROCESS_BASIC_INFORMATION <>
mbi MEMORY_BASIC_INFORMATION <>
DBEvent DEBUG_EVENT <>

align dword
context CONTEXT <>


    .code


start:

invoke GetModuleHandle, NULL
mov    hInstance,eax
invoke GetCurrentDirectory, 128, offset realdir

SetConsoleCaption offset ProgTitle
invoke GetStdHandle,STD_OUTPUT_HANDLE
invoke SetConsoleTextAttribute, eax, FOREGROUND_BLUE+FOREGROUND_GREEN+FOREGROUND_INTENSITY

invoke StdOut, offset ProgTitle
invoke StdOut, offset newline
invoke StdOut, offset newline

invoke GetPrivateProfileIntA,offset Antiantidebuggingstring,offset PEBBDstring,1,offset OptionsFileName
cmp eax,0
jne @dontskip1
inc byte ptr [PEBBDoptionskip]
inc byte ptr [ZWQPIoptionskip]
@dontskip1:

invoke GetPrivateProfileIntA,offset Antiantidebuggingstring,offset ZWQPIstring,1,offset OptionsFileName
test eax,eax
.IF eax==0 
    inc byte ptr [ZWQPIoptionskip]
.ENDIF   

invoke GetPrivateProfileIntA,offset Antiantidebuggingstring,offset ZWSITstring,1,offset OptionsFileName
test eax,eax
.IF eax==0 
    inc byte ptr [ZWSIToptionskip]
.ENDIF    


mov ofn.lStructSize,SIZEOF ofn
mov ofn.lpstrFilter, OFFSET FilterString
mov ofn.lpstrFile, OFFSET namebuffer
mov ofn.nMaxFile, 256h
mov ofn.nFilterIndex , 2
mov ofn.lpstrTitle , offset lpstrTitlestring
mov ofn.Flags, OFN_FILEMUSTEXIST + OFN_PATHMUSTEXIST + OFN_LONGNAMES + OFN_EXPLORER + OFN_FORCESHOWHIDDEN \
                  + OFN_HIDEREADONLY ;+ OFN_NOCHANGEDIR
invoke GetOpenFileName , offset ofn
test eax,eax
jz @exit
invoke GetCurrentDirectory, 128, offset targetdir

m2m FNamePtr, ofn.lpstrFile
invoke SetCurrentDirectory, offset realdir
invoke PathFileExists, offset exact_exeinfo_str
test eax,eax
jz @exeinfope_not_found
call @show_exeinfope_scan_result
@exeinfope_not_found:
invoke SetCurrentDirectory, offset targetdir

invoke GetStartupInfo,offset startinfo 
invoke CreateProcess,dword ptr [FNamePtr],0,0,0,FALSE,DEBUG_PROCESS+DEBUG_ONLY_THIS_PROCESS+CREATE_SUSPENDED,0,0,offset startinfo,offset pi
test eax,eax
je @exit_on_error

invoke dw2hex, [pi.dwProcessId], offset buffer
print "Process created, process ID : ",
print offset buffer,13,10,13,10

call @PEBBD_bit_patching
call @hook_ZWQIP
call @hook_ZWSIT
invoke ResumeThread, pi.hThread

.while TRUE
   invoke WaitForDebugEvent, addr DBEvent, INFINITE
   .if DBEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT
       invoke StdOut, offset TargetExitedText
       invoke MessageBox,0, offset TargetExitedText,offset ProgTitle , 0
       jmp @exit
   .elseif DBEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT

       invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_CONTINUE
       .continue
   .elseif DBEvent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT
            .if DBEvent.u.Exception.pExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT
                 invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED
                 .continue
            .elseif DBEvent.u.Exception.pExceptionRecord.ExceptionCode==STATUS_INVALID_HANDLE
                 call @handle_invalid_handle_exception
                 .continue
            .else
            	 invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED
                 .continue          
            .endif
   .elseif DBEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT
        invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_CONTINUE
        .continue
   .elseif DBEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT
        invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_CONTINUE
        .continue
   .else
   	    invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED
        .continue 
   .endif
.endw 
;######################################################################################################################

@exit:
invoke ExitProcess,0

@exit_on_error:
invoke MessageBox , 0 , offset error_msg , offset ProgTitle , MB_ICONSTOP
jmp @exit


@PEBBD_bit_patching:
.IF byte ptr [PEBBDoptionskip] == 0
   invoke LoadLibrary , offset ntdll_string
   mov dword ptr [NTDLLbase] , eax
   invoke GetProcAddress , dword ptr [NTDLLbase] , offset ntqip_string
   mov dword ptr [ntqip_address] , eax

   push offset tempdword
   push sizeof pbi
   push offset pbi
   push 0
   push pi.hProcess
   call dword ptr [ntqip_address]

   invoke VirtualProtectEx, pi.hProcess , pbi.PebBaseAddress , 1000h , PAGE_READWRITE , offset tempdword 

   mov ebx , pbi.PebBaseAddress
   test ebx,ebx
   jz @exit_on_error
   add ebx,2
   invoke WriteProcessMemory , pi.hProcess , EBX , offset bufferzerobyte , 1 , offset tempdword
   print "PEB   patching function completed",13,10
.ELSE
   print "PEB patching skipped",13,10
.ENDIF
ret


@hook_ZWQIP:
.IF byte ptr [ZWQPIoptionskip] == 0
   invoke VirtualAllocEx , pi.hProcess , NULL , 1000h , MEM_RESERVE+MEM_COMMIT , PAGE_EXECUTE_READWRITE     ; reserves space and pushes code cave address
   push eax
   mov byte ptr [buffer] , 0e9h                                                                             ; fills buffer with jmp to codecave address
   mov dword ptr [buffer+1], eax
   mov esi , dword ptr [ntqip_address]

   invoke VirtualProtectEx, pi.hProcess , ntqip_address , 64h , PAGE_EXECUTE_READWRITE , offset tempdword   ; unprotects memory of the API
   test eax,eax
   jz @exit_on_error
   invoke WriteProcessMemory , pi.hProcess , ntqip_address , offset buffer , 5 , offset tempdword           ; writes the jump to the code cave
   test eax,eax
   jz @exit_on_error
   pop eax                                                                                                  ; pops codecave address
   invoke WriteProcessMemory , pi.hProcess , EAX , offset zwqip_code_cave , 18h , offset tempdword          ; writes the code cave itself
   test eax,eax
   jz @exit_on_error
   print "ZWQIP patching function completed",13,10
.ELSE
   print "ZWQIP patching skipped",13,10
.ENDIF
ret

@hook_ZWSIT:
.IF byte ptr [ZWSIToptionskip] == 0
   invoke VirtualAllocEx , pi.hProcess , NULL , 1000h , MEM_RESERVE+MEM_COMMIT , PAGE_EXECUTE_READWRITE     ; reserves space and pushes code cave address
   push eax
   mov byte ptr [buffer] , 0e9h                                                                             ; fills buffer with jmp to codecave address
   mov dword ptr [buffer+1], eax
   mov esi , dword ptr [ntqip_address]

   invoke VirtualProtectEx, pi.hProcess , ntqip_address , 64h , PAGE_EXECUTE_READWRITE , offset tempdword   ; unprotects memory of the API
   test eax,eax
   jz @exit_on_error
   invoke WriteProcessMemory , pi.hProcess , ntqip_address , offset buffer , 5 , offset tempdword           ; writes the jump to the code cave
   test eax,eax
   jz @exit_on_error
   pop eax                                                                                                  ; pops codecave address
   invoke WriteProcessMemory , pi.hProcess , EAX , offset zwqip_code_cave , 18h , offset tempdword          ; writes the code cave itself
   test eax,eax
   jz @exit_on_error
   print "ZWSIT patching function completed",13,10,13,10
.ELSE
   print "ZWSIT patching skipped",13,10,13,10
.ENDIF
ret

@handle_invalid_handle_exception:
    mov eax, dword ptr [NTDLLbase]
    mov ebx , DBEvent.u.Exception.pExceptionRecord.ExceptionAddress
    cmp ebx,eax
    jl @not_in_ntdll
    sub eax,ebx
    cmp eax, 0AC000h
    jg @not_in_ntdll
    invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_CONTINUE           
    print "Not passing the invalid handle exception",13,10
ret
@not_in_ntdll:
    invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED
    print "Passing the artificial invalid handle exception to the proggy",13,10
ret


@show_exeinfope_scan_result:
print "Exeinfope.exe found in current folder, scanning ...",13,10
invoke szCopy, offset exeinfope_string, offset buffer
invoke szappend, offset buffer, dword ptr [FNamePtr], 0Fh
invoke szappend, offset buffer, offset exeinfope_params, EAX

invoke DeleteFile, offset epe_log_string
invoke WinExec, offset buffer, SW_HIDE
mov dword ptr [tempdword], InputFile(offset epe_log_string)
invoke StdOut, dword ptr [tempdword]
invoke StdOut, offset newline
invoke DeleteFile, offset epe_log_string
ret


ReadRegister	proc	Reg:DWORD
    invoke GetThreadContext,pi.hThread, offset context
	
	ret

ReadRegister endp

end start
