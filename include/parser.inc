;---------------------------------------------------------- v 0.0.1 ----
; PUBLIC

; Parse a script filling INSTRUCTION_LIST structure, and INSTRUCTION
Parser_ParseScript  PROTO   :DWORD, :DWORD, :DWORD, :DWORD
                            ;lpszFileName:   Offset to an asciiz file name to open.
                            ;lpszScriptName: Offset to an asciiz script name 
                            ;dwFlags:        Flags indicating how parser should manage in certains situations.
                            ;                For now its only accept PERSER_STOP_CRITICAL and PARSER_VIRTUAL_ALLOC.
                            ;                See PARSER PARAMETERS TABLE.
                            ;lpInstrEP:      Offset where to store(dword returned) an offset to parsed script instruction table, witch is
                            ;                just a list of pointers to current and next instruction structures.
                            
ParseScript     equ Parser_ParseScript
Parse           equ Parser_ParseScript

; Destroy memory allocated (if PARSER_VIRTUAL_ALLOC) or zeroed it.
Parser_Destroy      PROTO   :DWORD
                            ;lpInstrEP:      Offset returned by Parser_ParseScript function in lpInstrEP.

PARSER_VERSION              equ     00000001b
PARSER_MAXBUFFER_MEMORY     equ     2048
PARSER_MAX_ARGS             equ     4

; PARSER PARAMETERS TABLE
PARSER_STOP_CRITICAL        equ     0000001b
PARSER_VIRTUAL_ALLOC        equ     0000010b
PARSER_RESERVED1            equ     0000100b
PARSER_RESERVED2            equ     0001000b
PARSER_RESERVED3            equ     0010000b
PARSER_RESERVED4            equ     0100000b
PARSER_RESERVED5            equ     1000000b

; PARSER ERRORS RETURNS TABLE
PARSER_ERR_SUCCESS          equ     0
PARSER_ERR_UNDETERMINED     equ     1001
PARSER_ERR_BUFFER_OVERFLOW  equ     1002
PARSER_ERR_NO_BUFFER        equ     1003
PARSER_ERR_NO_FILE          equ     1004
PARSER_ERR_NO_SCRIPT_FOUND  equ     1005
PARSER_ERR_BAD_INSTR_FORMAT equ     1006
PARSER_ERR_UNKNOW_INSTR     equ     1007

;-----------------------------------------------------------------------
; PRIVATE

; Alloc memory to hold instr structures -> Parser_ParseScript
_Parser_Alloc_Memory     PROTO  :DWORD, :DWORD, :DWORD
; Delete allocated memory for instr structure -> Parser_Destroy
_Parser_Free_Memory      PROTO  :DWORD, :DWORD
; Read given ini file -> Parser_ParseScript
_Parser_Read_File        PROTO  :DWORD, :DWORD, :DWORD, :DWORD
; Take a string and fill instr struture with interpreted commands -> Parser_ParseScript  
_Parser_Interpret_Instr  PROTO  :DWORD, :DWORD, :DWORD
; Take interpreted commands and determine if they are valid -> Parser_ParseScript
_Parser_Validate_Instr   PROTO  :DWORD

;-----------------------------------------------------------------------

INSTRUCTION         STRUCT
    ;dwFlag      dword   ?
    dwCmnd      dword   ?
    dwType      dword   ?
    dwArgsType  dword   ?
    dwParam1    dword   ?
    dwParam2    dword   ?
    dwParam3    dword   ?
    dwParam4    dword   ?
    dwReserved  dword   10 dup(?)
INSTRUCTION         ENDS
INSTRUCTION_SIZE    equ sizeof INSTRUCTION

INSTRUCTION_LIST    STRUCT
    Instruction       INSTRUCTION <?>
    Previous_Instr    dword   ?
    Next_Instr        dword   ?
INSTRUCTION_LIST    ENDS
INSTRUCTION_LIST_SIZE   equ sizeof INSTRUCTION_LIST

;-----------------------------------------------------------------------

include     parser_instr.inc
include     parser_instr_def.inc
;-----------------------------------------------------------------------
