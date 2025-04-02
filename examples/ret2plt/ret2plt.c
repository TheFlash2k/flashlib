// gcc -o ret2plt -fno-stack-protector -no-pie ret2plt.c

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[], char* envp) {
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);

	char buf[100];

	puts("Ret2PLT example.");
	printf(">> ");
	gets(buf);
	return 0;
}
