;---------------------------------------------------------- v 0.0.1 ----
; PUBLIC
; Instructions currently supported
HWBP    equ     100     ; HWBP 
LOG     equ     101

;-----------------------------------------------------------------------
; PRIVATE
; Type of instrucions
_INSTR_TYPE_ATOM    equ     0001        ; instr (no arguments)
; _INSTR_TYPE_ATOM definition:
; Atomic instructions as: STD, CLD, STC, etc.
; No arguments.
_INSTR_TYPE_SIMPLE  equ     0002        ; instr + arg (reg)
; _INSTR_TYPE_SIMPLE definition:
; Simple instruction as: inc, dec, push, pop, etc.
; Arguments can be: reg
_INSTR_TYPE_COMPLEX equ     0004        ; instr + 2 args
; _INSTR_TYPE_COMPLEX definition:
; Complex instructoins as: sub, add, mov, lea, test, or, etc.
; Arguments can be: reg/imm, reg/mem, reg/reg; mem/imm, mem/reg, mem/mem
_INSTR_TYPE_COND    equ     0008        ; IF XXX (>=, <=, ==, !=) XXX
; _INSTR_TYPE_COND definiton:
; Conditional structures as: IFE, IFNE, IFGE, IFBE, IFG, IFB
; Arguments can be: reg/reg, reg/imm, reg/mem; mem/mem, mem/reg, mem/imm
_INSTR_TYPE_LOOP    equ     0016        ; LOOPE XXX, LOOPZ XXX, LOOPNE XXX, LOOPNZ XXX
; Loop instruction as: LOOPE, LOOPZ, LOOPNE, LOOPNZ
; Arguments can be: reg/reg, reg/mem, reg/imm; mem/reg, mem/mem, mem/imm
;_INSTR_TYPE_UNKNOW  equ     0008        ; bad instruction - unused

;-----------------------------------------------------------------------
; Type of arguments
_INSTR_ARGS_MEM     equ     1000
_INSTR_ARGS_REG     equ     2000
_INSTR_ARGS_IMM     equ     4000
_INSTR_ARGS_CUSTOM  equ     8000

_INSTR_ARGS_MEM_IMM equ     _INSTR_ARGS_MEM OR _INSTR_ARGS_IMM
_INSTR_ARGS_MEM_REG equ     _INSTR_ARGS_MEM OR _INSTR_ARGS_REG
_INSTR_ARGS_MEM_MEM equ     _INSTR_ARGS_MEM OR _INSTR_ARGS_MEM

_INSTR_ARGS_REG_IMM equ     _INSTR_ARGS_REG OR _INSTR_ARGS_IMM
_INSTR_ARGS_REG_MEM equ     _INSTR_ARGS_REG OR _INSTR_ARGS_MEM
_INSTR_ARGS_REG_REG equ     _INSTR_ARGS_REG OR _INSTR_ARGS_REG

;-----------------------------------------------------------------------
; Instruction default
INSTR_DEF    struct
    _instr_name      db 5 dup(?)
    _instr_id        dd ?
    _instr_type      dd ?
    _instr_type_args dd ?
    _instr_param1    dd ?
    _instr_param2    dd ?
    _instr_param3    dd ?
    _instr_param4    dd ?
    _instr_reserved  dd 10 dup (?)
INSTR_DEF    ends

; not implemented yet
INSTR_TABLE    struct
    _number_entries    dd  ?
    _addr              dd  ?
INSTR_TABLE     ends

;-----------------------------------------------------------------------
; Regs param ids
REGS_DEF    struc
    _reg_name   db  5   dup (?)
    _reg_size   dd  ?   ; unused yet
    _reg_id     dd  ?
REGS_DEF    ends
;----------------------------------------------------------------------- 
_INSTR_ARG_REG_EAX  equ     _INSTR_ARGS_REG OR 0100
_INSTR_ARG_REG_AX   equ     _INSTR_ARGS_REG OR 0110
_INSTR_ARG_REG_AH   equ     _INSTR_ARGS_REG OR 0120
_INSTR_ARG_REG_AL   equ     _INSTR_ARGS_REG OR 0130

_INSTR_ARG_REG_ECX  equ     _INSTR_ARGS_REG OR 0200
_INSTR_ARG_REG_CX   equ     _INSTR_ARGS_REG OR 0210
_INSTR_ARG_REG_CH   equ     _INSTR_ARGS_REG OR 0220
_INSTR_ARG_REG_CL   equ     _INSTR_ARGS_REG OR 0230

_INSTR_ARG_REG_EDX  equ     _INSTR_ARGS_REG OR 0300
_INSTR_ARG_REG_DX   equ     _INSTR_ARGS_REG OR 0310
_INSTR_ARG_REG_DH   equ     _INSTR_ARGS_REG OR 0320
_INSTR_ARG_REG_DL   equ     _INSTR_ARGS_REG OR 0330

_INSTR_ARG_REG_EBX  equ     _INSTR_ARGS_REG OR 0400
_INSTR_ARG_REG_BX   equ     _INSTR_ARGS_REG OR 0410
_INSTR_ARG_REG_BH   equ     _INSTR_ARGS_REG OR 0420
_INSTR_ARG_REG_BL   equ     _INSTR_ARGS_REG OR 0430

_INSTR_ARG_REG_ESP  equ     _INSTR_ARGS_REG OR 0500
_INSTR_ARG_REG_SP   equ     _INSTR_ARGS_REG OR 0510

_INSTR_ARG_REG_EBP  equ     _INSTR_ARGS_REG OR 0600
_INSTR_ARG_REG_BP   equ     _INSTR_ARGS_REG OR 0610

_INSTR_ARG_REG_ESI  equ     _INSTR_ARGS_REG OR 0700
_INSTR_ARG_REG_SI   equ     _INSTR_ARGS_REG OR 0710

_INSTR_ARG_REG_EDI  equ     _INSTR_ARGS_REG OR 0800
_INSTR_ARG_REG_DI   equ     _INSTR_ARGS_REG OR 0810

;-----------------------------------------------------------------------
; Custom params
CUSTOM_DEF  struct
    _custom_name    db  10   dup (?)
    _custom_id      dd  ?
CUSTOM_DEF  ends
;-----------------------------------------------------------------------
_INSTR_ARG_MEMEX    equ _INSTR_ARGS_CUSTOM OR 0010     
_INSTR_ARG_MEMREAD  equ _INSTR_ARGS_CUSTOM OR 0011
_INSTR_ARG_MEMWRITE equ _INSTR_ARGS_CUSTOM OR 0012

;-----------------------------------------------------------------------
