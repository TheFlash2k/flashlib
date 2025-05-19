#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_BUF_SIZE 0x100

void vuln() {
    FILE* fp = fopen("flag.txt", "r");
    char flag[MAX_BUF_SIZE] = { 0 };
    char buf[MAX_BUF_SIZE];
    fread(flag, MAX_BUF_SIZE, sizeof(char), fp);

    printf("Whomst may you be: ");
    fgets(buf, MAX_BUF_SIZE-0x1, stdin);
    printf(buf);
}

int main(int argc, char* argv[], char* envp) {
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);
    vuln();
    return 0;
}