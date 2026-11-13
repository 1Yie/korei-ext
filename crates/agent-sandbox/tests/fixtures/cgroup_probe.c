#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 10;
    int ready[2];
    if (pipe(ready)) return 11;
    pid_t first = fork();
    if (first < 0) return 12;
    if (first == 0) {
        close(ready[0]);
        if (setsid() < 0) _exit(13);
        pid_t second = fork();
        if (second < 0) _exit(14);
        if (second > 0) _exit(0);
        int marker = open(argv[2], O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (marker < 0) _exit(15);
        puts("ready");
        fflush(stdout);
        if (write(ready[1], "1", 1) != 1) _exit(16);
        close(ready[1]);
        for (;;) {
            if (write(marker, "x", 1) != 1) _exit(17);
            usleep(10000);
        }
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 18;
    close(ready[0]);
    if (strcmp(argv[1], "exit") == 0) return 0;
    for (;;) pause();
}
