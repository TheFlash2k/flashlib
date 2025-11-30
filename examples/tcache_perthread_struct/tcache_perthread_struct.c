// gcc -o tcache_perthread_struct tcache_perthread_struct.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char* argv[], char* envp) {

	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);

	void *chunk = malloc(0x20);
	printf("allocated chunk @ %p\n", chunk);

	char* perthread_struct = (void*)(((unsigned long )chunk - 0x2a0) + 0x10);
	printf("tcache_perthread_struct @ %p\n", perthread_struct);

	printf("data: ");
	ssize_t n = read(STDIN_FILENO, perthread_struct, 0x300);
	if(perthread_struct[n] == '\n')   perthread_struct[n] = 0;
	if(perthread_struct[n-1] == '\n') perthread_struct[n-1] = 0;

	printf("Which bin do you want to allocate from? (0x20-0x410): ");
	uint64_t bin_size;
	scanf("%llx%*c", &bin_size);
	printf("Allocating from 0x%llx bin\n", bin_size);
	if(bin_size % 0x10 != 0)
		bin_size -= (bin_size % 0x10);
	void *chunk2 = malloc(bin_size-0x8);
	printf("Chunk2 allocated @ %p\n", chunk2);
	printf("Done!\nPress any key to exit!");
	getchar();
}
