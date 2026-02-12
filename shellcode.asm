.code

PUBLIC ShellcodeStart
PUBLIC ShellcodeEnd
PUBLIC ShellcodeSize

ShellcodeStart PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 28h
    
    call Shellcode
    
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ShellcodeStart ENDP

ShellcodeEnd:

END
