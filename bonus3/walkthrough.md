# Bonus 3





```sh
(gdb) info func
All defined functions:

Non-debugging symbols:
0x0804836c  _init
0x080483b0  strcmp
0x080483b0  strcmp@plt
0x080483c0  fclose
0x080483c0  fclose@plt
0x080483d0  fread
0x080483d0  fread@plt
0x080483e0  puts
0x080483e0  puts@plt
0x080483f0  __gmon_start__
0x080483f0  __gmon_start__@plt
0x08048400  __libc_start_main
0x08048400  __libc_start_main@plt
0x08048410  fopen
0x08048410  fopen@plt
0x08048420  execl
0x08048420  execl@plt
0x08048430  atoi
0x08048430  atoi@plt
0x08048440  _start
0x08048470  __do_global_dtors_aux
0x080484d0  frame_dummy
0x080484f4  main
0x08048620  __libc_csu_init
0x08048690  __libc_csu_fini
0x08048692  __i686.get_pc_thunk.bx
0x080486a0  __do_global_ctors_aux
0x080486cc  _fini
(gdb) 
```

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x080484f4 <+0>:	push   ebp
   0x080484f5 <+1>:	mov    ebp,esp
   0x080484f7 <+3>:	push   edi
   0x080484f8 <+4>:	push   ebx
   0x080484f9 <+5>:	and    esp,0xfffffff0
   0x080484fc <+8>:	sub    esp,0xa0
   0x08048502 <+14>:	mov    edx,0x80486f0
   0x08048507 <+19>:	mov    eax,0x80486f2
   0x0804850c <+24>:	mov    DWORD PTR [esp+0x4],edx
   0x08048510 <+28>:	mov    DWORD PTR [esp],eax
   0x08048513 <+31>:	call   0x8048410 <fopen@plt>
   0x08048518 <+36>:	mov    DWORD PTR [esp+0x9c],eax
   0x0804851f <+43>:	lea    ebx,[esp+0x18]
   0x08048523 <+47>:	mov    eax,0x0
   0x08048528 <+52>:	mov    edx,0x21
   0x0804852d <+57>:	mov    edi,ebx
   0x0804852f <+59>:	mov    ecx,edx
   0x08048531 <+61>:	rep stos DWORD PTR es:[edi],eax
   0x08048533 <+63>:	cmp    DWORD PTR [esp+0x9c],0x0
   0x0804853b <+71>:	je     0x8048543 <main+79>
   0x0804853d <+73>:	cmp    DWORD PTR [ebp+0x8],0x2
   0x08048541 <+77>:	je     0x804854d <main+89>
   0x08048543 <+79>:	mov    eax,0xffffffff
   0x08048548 <+84>:	jmp    0x8048615 <main+289>
   0x0804854d <+89>:	lea    eax,[esp+0x18]
   0x08048551 <+93>:	mov    edx,DWORD PTR [esp+0x9c]
   0x08048558 <+100>:	mov    DWORD PTR [esp+0xc],edx
   0x0804855c <+104>:	mov    DWORD PTR [esp+0x8],0x42
   0x08048564 <+112>:	mov    DWORD PTR [esp+0x4],0x1
   0x0804856c <+120>:	mov    DWORD PTR [esp],eax
   0x0804856f <+123>:	call   0x80483d0 <fread@plt>
   0x08048574 <+128>:	mov    BYTE PTR [esp+0x59],0x0
   0x08048579 <+133>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804857c <+136>:	add    eax,0x4
   0x0804857f <+139>:	mov    eax,DWORD PTR [eax]
   0x08048581 <+141>:	mov    DWORD PTR [esp],eax
   0x08048584 <+144>:	call   0x8048430 <atoi@plt>
   0x08048589 <+149>:	mov    BYTE PTR [esp+eax*1+0x18],0x0
   0x0804858e <+154>:	lea    eax,[esp+0x18]
   0x08048592 <+158>:	lea    edx,[eax+0x42]
   0x08048595 <+161>:	mov    eax,DWORD PTR [esp+0x9c]
   0x0804859c <+168>:	mov    DWORD PTR [esp+0xc],eax
   0x080485a0 <+172>:	mov    DWORD PTR [esp+0x8],0x41
   0x080485a8 <+180>:	mov    DWORD PTR [esp+0x4],0x1
---Type <return> to continue, or q <return> to quit---
   0x080485b0 <+188>:	mov    DWORD PTR [esp],edx
   0x080485b3 <+191>:	call   0x80483d0 <fread@plt>
   0x080485b8 <+196>:	mov    eax,DWORD PTR [esp+0x9c]
   0x080485bf <+203>:	mov    DWORD PTR [esp],eax
   0x080485c2 <+206>:	call   0x80483c0 <fclose@plt>
   0x080485c7 <+211>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080485ca <+214>:	add    eax,0x4
   0x080485cd <+217>:	mov    eax,DWORD PTR [eax]
   0x080485cf <+219>:	mov    DWORD PTR [esp+0x4],eax
   0x080485d3 <+223>:	lea    eax,[esp+0x18]
   0x080485d7 <+227>:	mov    DWORD PTR [esp],eax
   0x080485da <+230>:	call   0x80483b0 <strcmp@plt>
   0x080485df <+235>:	test   eax,eax
   0x080485e1 <+237>:	jne    0x8048601 <main+269>
   0x080485e3 <+239>:	mov    DWORD PTR [esp+0x8],0x0
   0x080485eb <+247>:	mov    DWORD PTR [esp+0x4],0x8048707
   0x080485f3 <+255>:	mov    DWORD PTR [esp],0x804870a
   0x080485fa <+262>:	call   0x8048420 <execl@plt>
   0x080485ff <+267>:	jmp    0x8048610 <main+284>
   0x08048601 <+269>:	lea    eax,[esp+0x18]
   0x08048605 <+273>:	add    eax,0x42
   0x08048608 <+276>:	mov    DWORD PTR [esp],eax
   0x0804860b <+279>:	call   0x80483e0 <puts@plt>
   0x08048610 <+284>:	mov    eax,0x0
   0x08048615 <+289>:	lea    esp,[ebp-0x8]
   0x08048618 <+292>:	pop    ebx
   0x08048619 <+293>:	pop    edi
   0x0804861a <+294>:	pop    ebp
   0x0804861b <+295>:	ret    
End of assembler dump.
(gdb)
```


This one is also kind heavy.


```sh
bonus3@RainFall:~$ ./bonus3 
bonus3@RainFall:~$ ./bonus3 kik

bonus3@RainFall:~$ ./bonus3 kiklll

bonus3@RainFall:~$ ./bonus3 kiklll lol
bonus3@RainFall:~$ ./bonus3 kiklll lol lol
bonus3@RainFall:~$
```
When there is one argument it prints a '\n'.



```c
undefined4 main(int param_1,int param_2)
{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  byte bVar4;
  undefined4 local_98 [16];
  undefined local_57;
  char local_56 [66];
  FILE *local_14;
  
  bVar4 = 0;
  local_14 = fopen("/home/user/end/.pass","r");
  puVar3 = local_98;
  for (iVar2 = 0x21; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + (uint)bVar4 * -2 + 1;
  }
  if ((local_14 == (FILE *)0x0) || (param_1 != 2)) {
    uVar1 = 0xffffffff;
  }
  else {
    fread(local_98,1,0x42,local_14);
    local_57 = 0;
    iVar2 = atoi(*(char **)(param_2 + 4));
    *(undefined *)((int)local_98 + iVar2) = 0;
    fread(local_56,1,0x41,local_14);
    fclose(local_14);
    iVar2 = strcmp((char *)local_98,*(char **)(param_2 + 4));
    if (iVar2 == 0) {
      execl("/bin/sh","sh",0);
    }
    else {
      puts(local_56);
    }
    uVar1 = 0;
  }
  return uVar1;
}
```


The program opens the last password, but also execute a shell, when certain condition ar met.

We will take the first open door we see.

After reviewing the code, the program actually do an atoi on av[1] lets try overflowing with big or negative integer.

Using GDB is quite hard here, the program opens a file that only the 'end' user can access, and since binary is SUID, using a debugger will quit the program since it quit if it doesn't succeed at opening the file.

So the only way to test our input is to edit the file the program is trying to access, we are to give it our own like this :


```sh
(gdb) br *main+28
Breakpoint 1 at 0x8048510
(gdb) run l
Starting program: /home/user/bonus3/bonus3 l

Breakpoint 1, 0x08048510 in main ()
(gdb) p $eax
$1 = 134514418
(gdb) x/s $eax
0x80486f2:	 "/home/user/end/.pass"
(gdb) set $eax = "/tmp/fichier"
(gdb) p $eax
$2 = 134520840
(gdb) continue
Continuing.

[Inferior 1 (process 4954) exited normally]
```

From there we can test our input.

