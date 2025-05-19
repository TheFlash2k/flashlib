#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_BUF_SIZE 0x100

uint32_t menu() {
    puts("1. Read");
    puts("2. Trigger");
    puts("3. Read Flag");
    puts("0. Exit");
    printf(">> ");

    uint32_t choice;
    scanf("%d%*c", &choice);
    return choice;
}

void vuln() {
    /*
        This is just to simulate a scenario where we have to do a certain
        steps before the format string itself is triggered.
    */
   FILE* fp;
   char buf[MAX_BUF_SIZE];
   char flag[MAX_BUF_SIZE];
   while(1) {
        switch(menu()) {
            case 1:
                printf("$ ");
                fgets(buf, MAX_BUF_SIZE-0x1, stdin);
                break;
            case 2:
                printf(buf);
                break;
            case 3:
                fp = fopen("flag.txt", "r");
                fread(flag, MAX_BUF_SIZE, sizeof(char), fp);
                puts("Read flag successfully!");
                fclose(fp);
                break;
            case 0:
            default:
                exit(0);
        }
   }
}

int main(int argc, char* argv[], char* envp) {
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stderr, 0, _IONBF, 0);
    vuln();
    return 0;
}