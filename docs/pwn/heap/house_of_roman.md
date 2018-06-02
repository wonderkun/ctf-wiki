

# House of Roman

## 介绍

House of Roman 这个技巧说简单点其实就是 fastbin attack 和 Unsortbin attachk 结合的一个小 trick。

## 概括



该技术用于 bypass ALSR，利用12-bit 的爆破来达到获取shell的目的。且仅仅只需要一个 UAF 漏洞以及能创建任意大小的 chunk 的情况下就能完成利用。



## 原理以及展示



作者提供给了我们一个 demo 用于展示，整个利用过程大概可以分为三步骤。

1. 将 FD 指向 malloc_hook
2. 修正 0x71 的 Freelist
3. 往 malloc_hook 写入 one gadget



先对 demo 进行一个大致的分析：

开启的保护情况：

```bash
[*] '/media/psf/Home/Desktop/MyCTF/House-Of-Roman/new_chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

样题中有三个主要功能，Malloc ，Write，以及 Free。

```c
    switch ( v4 )
    {
      case 1:
        puts("Malloc");
        v5 = malloc_chunk("Malloc");
        if ( !v5 )
          puts("Error");
        break;
      case 2:
        puts("Write");
        write_chunk("Write");
        break;
      case 3:
        puts("Free");
        free_chunk();
        break;
      default:
        puts("Invalid choice");
        break;
```

在 Free 功能中存在 指针未置零而造成的悬挂指针。

```c
void free_chunk()
{
  unsigned int v0; // [rsp+Ch] [rbp-4h]@1

  printf("\nEnter index :");
  __isoc99_scanf("%d", &v0);
  if ( v0 <= 0x13 )
    free(heap_ptrs[(unsigned __int64)v0]);
}
```



### 第一步

首先伪造一个 chunk  ，chunk的大小为0x61。紧接着我们利用 partial overwrite 将 FD 指向伪造的chunk（当然，这里我们也可以用 UAF 完成）。

伪造 chunk size

```bash
pwndbg>
0x555555757050: 0x41414141      0x41414141      0x41414141      0x41414141
0x555555757060: 0x41414141      0x41414141      0x41414141      0x41414141
0x555555757070: 0x41414141      0x41414141      0x41414141      0x41414141
0x555555757080: 0x41414141      0x41414141      0x41414141      0x41414141
0x555555757090: 0x41414141      0x41414141      0x61    0x0     <----------
```

这里，我们 free 掉 chunk 1，这个时候我们能获得一个 unsortbin

```
0x555555757020 PREV_INUSE {
  prev_size = 0x0,
  size = 0xd1,
  fd = 0x7ffff7dd1b58 <main_arena+88>,
  bk = 0x7ffff7dd1b58 <main_arena+88>,
  fd_nextsize = 0x4141414141414141,
  bk_nextsize = 0x4141414141414141
}
```

接着，我们重分配 0xd1 这块 chunk，以及修改其 size 为0x71

```
pwndbg> x/40ag 0x555555757020
0x555555757020: 0x4141414141414141      0x71
0x555555757030: 0x7ffff7dd1b58 <main_arena+88>  0x7ffff7dd1b58 <main_arena+88>
0x555555757040: 0x4141414141414141      0x4141414141414141
0x555555757050: 0x4141414141414141      0x4141414141414141
0x555555757060: 0x4141414141414141      0x4141414141414141
0x555555757070: 0x4141414141414141      0x4141414141414141
0x555555757080: 0x4141414141414141      0x4141414141414141
0x555555757090: 0x4141414141414141      0x61
```



我们紧接着需要修正这0x71 FD freelist ，将其伪造成已经释放的块

```
pwndbg> x/40ag 0x555555757000
0x555555757000: 0x0     0x21
0x555555757010: 0x4141414141414141      0x4141414141414141
0x555555757020: 0x4141414141414141      0x71       <----------  free 0x71
0x555555757030: 0x7ffff7dd1b58 <main_arena+88>  0x7ffff7dd1b58 <main_arena+88>
0x555555757040: 0x4141414141414141      0x4141414141414141
0x555555757050: 0x4141414141414141      0x4141414141414141
0x555555757060: 0x4141414141414141      0x4141414141414141
0x555555757070: 0x4141414141414141      0x4141414141414141
0x555555757080: 0x4141414141414141      0x4141414141414141
0x555555757090: 0x4141414141414141      0x61
0x5555557570a0: 0x0     0x0
0x5555557570b0: 0x0     0x0
0x5555557570c0: 0x0     0x0
0x5555557570d0: 0x0     0x0
0x5555557570e0: 0x0     0x0
0x5555557570f0: 0xd0    0x71   <----------     free 0x71
0x555555757100: 0x0     0x0
0x555555757110: 0x0     0x0
0x555555757120: 0x0     0x0
0x555555757130: 0x0     0x0

```



```
libc : 0x7ffff7a23d28 ("malloc_hook")
```

这个时候我们的 FD 已经在 malloc hook 附近，未之后的爆破做准备。

### 第二步

我们只需要通过 释放一块0x71大小的 chunk 就能完成 fix。



### 第三步

利用 unsortebin 的攻击技巧，并使用编辑功能将 onegadet 写入	。





## link

https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc

https://github.com/romanking98/House-Of-Roman