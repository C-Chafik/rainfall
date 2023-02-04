# Level 0

First level, i tried what i learned in Snow-Crash


The debugger ltrace, strace, doesn't work, and valgrind is not installed, so i used GDB.


Using GDB i first saw that the binary used atoi in the first place, if you dont provide any argument to the binary it will segfault.


```s
level0@RainFall:~$ ./level0 
Segmentation fault (core dumped)
level0@RainFall:~$ 
```


And if you provide on or more :
```s
No !
```

Lets check the assembly code :

```asm
0x08048ec0 <+0>:	push   %ebp
0x08048ec1 <+1>:	mov    %esp,%ebp
0x08048ec3 <+3>:	and    $0xfffffff0,%esp
0x08048ec6 <+6>:	sub    $0x20,%esp
0x08048ec9 <+9>:	mov    0xc(%ebp),%eax
0x08048ecc <+12>:	add    $0x4,%eax
0x08048ecf <+15>:	mov    (%eax),%eax
0x08048ed1 <+17>:	mov    %eax,(%esp)
0x08048ed4 <+20>:	call   0x8049710 <atoi>
0x08048ed9 <+25>:	cmp    $0x1a7,%eax
0x08048ede <+30>:	jne    0x8048f58 <main+152>
0x08048ee0 <+32>:	movl   $0x80c5348,(%esp)
0x08048ee7 <+39>:	call   0x8050bf0 <strdup>
0x08048eec <+44>:	mov    %eax,0x10(%esp)
0x08048ef0 <+48>:	movl   $0x0,0x14(%esp)
0x08048ef8 <+56>:	call   0x8054680 <getegid>
0x08048efd <+61>:	mov    %eax,0x1c(%esp)
0x08048f01 <+65>:	call   0x8054670 <geteuid>
0x08048f06 <+70>:	mov    %eax,0x18(%esp)
0x08048f0a <+74>:	mov    0x1c(%esp),%eax
(...)
```

This is just a fragment but you can see it use atoi to our argument, and them make a cmp with 0x1a7, that's actually a integer constant.

When we translate it it give us this value :

```
7 x 1 = 7
A x 16 = 160
1 x 16 x 16 = 256

7 + 160 + 256 = 423

= 423
```

Lets try :


```s
level0@RainFall:~$ ./level0 423
$ id
uid=2030(level1) gid=2020(level0) groups=2030(level1),100(users),2020(level0)
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$
```

When we gave him 423 it opened us a shell, and when we check the id, it opened it as level1 !

Nothing too hard here, just had to cat the password and go to the next level.