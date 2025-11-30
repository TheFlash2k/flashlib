// gcc -o bruteforce -w -Wl,-z,relro,-z,lazy -fPIE -fPIC bruteforce.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void win() {
    execve("/bin/sh", NULL, NULL);
}

void vuln() {
    printf("elf leak: %lld\n", &win);
    unsigned long addr;
    printf("addr: ");
    scanf("%lld", &addr);
    printf("word: ");
    scanf("%hd", addr);
    exit(0);
}

int main(int argc, char* argv[], char* envp) {
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);
    vuln();
    return 0;
}