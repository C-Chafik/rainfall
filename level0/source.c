
int main(int ac, char **av)
{
    if ( atoi(av[0]) == 423 )
    {
        char *s = strdrup("/bin/sh");
        int effective = getegid();
        int real = geteuid();
        setresgid(effective);
        setresuid(real);
        execve("/bin/sh", &s);
    }
    else
        write(2, "No !\n", 5);
    return 0;
}