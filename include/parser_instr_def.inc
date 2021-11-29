; PRIVATE
.const
    hINSTR_TABLE    INSTR_DEF <"HWBP", HWBP, _INSTR_TYPE_SIMPLE, _INSTR_ARGS_MEM OR _INSTR_ARGS_REG, ?, ?, ?, ?>
                    INSTR_DEF <"LOG", LOG, _INSTR_TYPE_SIMPLE, _INSTR_ARGS_REG, ?, ?, ?, ?>

    ;Instr_Table INSTR_TABLE <2, offset hInstrs_Table> 

    hREG_TABLE  REGS_DEF <"EAX", 32, _INSTR_ARG_REG_EAX>
                REGS_DEF <"AX", 16, _INSTR_ARG_REG_AX>
                REGS_DEF <"AH", 8, _INSTR_ARG_REG_AH>
                REGS_DEF <"AL", 8, _INSTR_ARG_REG_AL>
                
                REGS_DEF <"ECX", 32, _INSTR_ARG_REG_ECX>
                REGS_DEF <"CX", 16, _INSTR_ARG_REG_CX>
                REGS_DEF <"CH", 8, _INSTR_ARG_REG_CH>
                REGS_DEF <"CL", 8, _INSTR_ARG_REG_CL>
                
                REGS_DEF <"EDX", 32, _INSTR_ARG_REG_EDX>
                REGS_DEF <"DX", 16, _INSTR_ARG_REG_DX>
                REGS_DEF <"DH", 8, _INSTR_ARG_REG_DH>
                REGS_DEF <"DL", 8, _INSTR_ARG_REG_DL>
                
                REGS_DEF <"EBX", 32, _INSTR_ARG_REG_EBX>
                REGS_DEF <"BX", 16, _INSTR_ARG_REG_BX>
                REGS_DEF <"BH", 8, _INSTR_ARG_REG_BH>
                REGS_DEF <"BL", 8, _INSTR_ARG_REG_BL>
                
                REGS_DEF <"ESP", 32, _INSTR_ARG_REG_ESP>
                REGS_DEF <"SP", 16, _INSTR_ARG_REG_SP>
                
                REGS_DEF <"EBP", 32, _INSTR_ARG_REG_EBP>
                REGS_DEF <"BP", 16, _INSTR_ARG_REG_BP>
                
                REGS_DEF <"ESI", 32, _INSTR_ARG_REG_ESI>
                REGS_DEF <"SI", 16, _INSTR_ARG_REG_SI>

                REGS_DEF <"EDI", 32, _INSTR_ARG_REG_EDI>
                REGS_DEF <"DI", 16, _INSTR_ARG_REG_DI>

    hCUSTOM_PARAMS  CUSTOM_DEF <"MEMEX", _INSTR_ARG_MEMEX>
                    CUSTOM_DEF <"MEMREAD", _INSTR_ARG_MEMEX>
                    CUSTOM_DEF <"MEMWRITE", _INSTR_ARG_MEMEX>
;-----------------------------------------------------------------------
