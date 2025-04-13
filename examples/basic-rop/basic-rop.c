// gcc -o basic-rop -fno-stack-protector -no-pie basic-rop.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void vuln() {
    char buf[100];
    printf("Leak: %p\n> ", printf);
    read(STDIN_FILENO, buf, 0x100);
}

int main(int argc, char* argv[], char* envp) {
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);
    vuln();
    return 0;
}