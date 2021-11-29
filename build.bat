@SET MASM32=\masm32

@"%MASM32%\bin\ml" /c /coff /Cp /nologo Cylon.asm
@"%MASM32%\bin\link" /SUBSYSTEM:CONSOLE  /LIBPATH:"%MASM32%\lib" Cylon.obj rsrc.RES
@pause
