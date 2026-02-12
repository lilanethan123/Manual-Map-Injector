import re

with open('shellcode_raw.txt', 'r') as f:
    data = f.read()

bytes_list = re.findall(r'0x[0-9A-Fa-f]{2}', data)

with open('shellcode.h', 'w') as f:
    f.write('#pragma once\n\n')
    f.write('extern "C" unsigned char Shellcode[] = {\n    ')
    
    for i, byte in enumerate(bytes_list):
        if i > 0 and i % 12 == 0:
            f.write('\n    ')
        f.write(byte)
        if i < len(bytes_list) - 1:
            f.write(', ')
    
    f.write('\n};\n\n')
    f.write(f'extern "C" unsigned int ShellcodeSize = {len(bytes_list)};\n')

print(f'[+] Generated shellcode.h with {len(bytes_list)} bytes')
