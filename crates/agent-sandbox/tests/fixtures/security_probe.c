#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int released;

static void *hold_thread(void *unused) {
    (void)unused;
    pthread_mutex_lock(&mutex);
    while (!released) pthread_cond_wait(&condition, &mutex);
    pthread_mutex_unlock(&mutex);
    return NULL;
}

static int task_probe(const char *mode, unsigned count) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NPROC, &limit) ||
        limit.rlim_cur != count + 1 || limit.rlim_max != count + 1) return 50;
    pid_t children[16];
    pthread_t threads[16];
    unsigned created = 0;
    int result = 0;
    int threaded = strcmp(mode, "tasks-thread") == 0;
    for (; created + 1 < count; ++created) {
        if (threaded) {
            if (pthread_create(&threads[created], NULL, hold_thread, NULL)) {
                result = 51;
                break;
            }
        } else {
            pid_t parent = getpid();
            pid_t child = fork();
            if (child == 0) {
                if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(60);
                for (;;) pause();
            }
            if (child < 0) { result = 52; break; }
            children[created] = child;
        }
    }
    if (!result && strcmp(mode, "tasks-wait") == 0) {
        puts("ready");
        fflush(stdout);
        for (;;) pause();
    }
    if (!result) {
        if (threaded) {
            pthread_t extra;
            int error = pthread_create(&extra, NULL, hold_thread, NULL);
            if (error != EAGAIN) {
                result = 53;
                if (!error) threads[created++] = extra;
            }
        } else {
            pid_t extra = fork();
            if (extra == 0) _exit(54);
            if (extra >= 0) { children[created++] = extra; result = 54; }
            else if (errno != EAGAIN) result = 55;
        }
    }
    if (threaded) {
        pthread_mutex_lock(&mutex);
        released = 1;
        pthread_cond_broadcast(&condition);
        pthread_mutex_unlock(&mutex);
        for (unsigned i = 0; i < created; ++i) pthread_join(threads[i], NULL);
    } else {
        for (unsigned i = 0; i < created; ++i) kill(children[i], SIGKILL);
        for (unsigned i = 0; i < created; ++i) {
            while (waitpid(children[i], NULL, 0) < 0) {
                if (errno != EINTR) { result = 56; break; }
            }
        }
    }
    if (!result) puts("limited");
    return result;
}
#endif

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "fork-denied") == 0) {
        pid_t child = fork();
        if (child < 0) {
            if (errno != EPERM && errno != EACCES) return 70;
            puts("fork-denied");
            return 0;
        }
        if (child == 0) {
            setsid();
            int marker = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (marker >= 0) {
                write(marker, "escaped", 7);
                close(marker);
            }
            _exit(71);
        }
        while (waitpid(child, NULL, 0) < 0) {
            if (errno != EINTR) return 72;
        }
        return 73;
    }
#if defined(__linux__)
    if (argc == 3 && strncmp(argv[1], "tasks-", 6) == 0) {
        char *end;
        unsigned long count = strtoul(argv[2], &end, 10);
        if (*end || count < 1 || count > 16 ||
            (strcmp(argv[1], "tasks-fork") &&
             strcmp(argv[1], "tasks-thread") &&
             strcmp(argv[1], "tasks-wait"))) return 49;
        return task_probe(argv[1], (unsigned)count);
    }
    if (argc == 3 && strcmp(argv[1], "bytes") == 0) {
        fwrite(argv[2], 1, strlen(argv[2]), stdout);
        return 0;
    }
    if (argc == 3 && (strcmp(argv[1], "launcher-low-hard") == 0 ||
                      strcmp(argv[1], "launcher-extra-task") == 0)) {
        if (strcmp(argv[1], "launcher-low-hard") == 0) {
            struct rlimit limit = {1, 1};
            if (setrlimit(RLIMIT_NPROC, &limit)) return 57;
        } else {
            pid_t parent = getpid();
            pid_t child = fork();
            if (child == 0) {
                if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(60);
                for (;;) pause();
            }
            if (child < 0) return 58;
        }
        execl("/.korei-launcher", "/.korei-launcher", "--max-processes", "1",
              "--", argv[2], "bytes", "effect", (char *)NULL);
        return 59;
    }
#endif
    if (argc == 2 && strcmp(argv[1], "rss") == 0) {
        size_t size = 128 * 1024 * 1024;
        volatile unsigned char *memory = malloc(size);
        if (!memory) return 90;
        for (size_t offset = 0; offset < size; offset += 4096) memory[offset] = 1;
        for (;;) pause();
    }
    if (argc != 4) return 1;
    if (getenv("HOME") || getenv("HUSK_SECURITY_SENTINEL")) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd >= 0) { close(fd); return 3; }
    fd = open(argv[1], O_WRONLY | O_TRUNC);
    if (fd >= 0) { close(fd); return 4; }
    fd = open(argv[2], O_RDONLY);
    if (fd >= 0) { close(fd); return 5; }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        int connected = connect(sock, (struct sockaddr *)&address, sizeof(address));
        close(sock);
        if (connected == 0 || (errno != EPERM && errno != EACCES)) return 6;
    } else if (errno != EPERM && errno != EACCES) return 7;
    pid_t child = fork();
    if (child == 0) _exit(91);
    if (child >= 0) return 8;
#if !defined(__APPLE__)
    struct rlimit limit;
    if (getrlimit(RLIMIT_AS, &limit) || limit.rlim_cur == RLIM_INFINITY) return 9;
    void *memory = mmap(NULL, (size_t)limit.rlim_cur + 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory != MAP_FAILED) { munmap(memory, (size_t)limit.rlim_cur + 4096); return 10; }
#endif
    puts("isolated");
    return 0;
}
