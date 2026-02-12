@echo off
ml64.exe /c /Fo shellcode.obj shellcode.asm
link.exe /dump /rawdata shellcode.obj | findstr "0x" > shellcode_raw.txt
python gen_shellcode.py
del shellcode.obj shellcode_raw.txt
echo [+] Shellcode.h generated
pause
