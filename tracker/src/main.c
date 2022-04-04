#include "tracker.h"
#include "utils.h"
#include "proc.h"
#include "validate.h"
#include "queue.h"
#include "email.h"
#include "message.h"
#include "proc_check.h"

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stddef.h>
#include <argp.h>
#include <sys/file.h>
#include <fcntl.h>

#define PRINT 0
#define MAX_PROCS 2048
#define PRINT_HASHES 0
#define PRINT_PACKAGES 0
#define PRINT_TIME 0
#define GENERATE_MESSAGES 1
#define SEND_EMAILS 1
#define SEND_SMS 1
#define VALIDATE_THREADS 4
#define COMPARE_THREADS 0

volatile int interrupt = 0;

void handle_signal(int signo) {
    signal(SIGINT, NULL);
    interrupt = 1;
}

int file_lock(const char *file, int *fd) {
    if ((*fd = open(file, O_RDWR | O_CREAT)) == -1) {
        fprintf(stderr, "Failed to open lock file\n");
        return 1;
    }

    if (flock(*fd, LOCK_EX | LOCK_NB) == -1) {
        fprintf(stderr, "An instance of this program is already running. Exiting...\n");
        return 1;
    }
    return 0;
}

int file_unlock(int fd) {
    if (flock(fd, LOCK_UN) == -1) {
        fprintf(stderr, "Failed to unlock file\n");
        return 1;
    }
    close(fd);
    return 0;
}

typedef struct Opts {
    char *server;
    long port;
    char *username;
    char *pasword;
    char *email;
} Opts;

const char *LOCKFILE = "/var/lock/tracker.lock";

static struct argp_option options[] =
{
    {"server", 's', "", 0, "SMTP Server"},
    {"port", 'p', "", 0, "SMTP Port"},
    {"username", 'u', "", 0, "Username"},
    {"password", 'w', "", 0, "Password"},
    {"email", 'e', "", 0, "Sender's Email"},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  Opts *opts = state->input;

  switch (key)
    {
    case 's':
        opts->server = arg;
        break;
    case 'p':
        opts->port = atol(arg);
        break;
    case 'u':
        opts->username = arg;
        break;
    case 'w':
        opts->pasword = arg;
        break;
    case 'e':
        opts->email = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    Opts opts;
    opts.server = "";
    opts.port = 0L;
    opts.username = "";
    opts.pasword = "";
    opts.email = "";

    struct argp argp = {options, parse_opt, "", "tracker -- A program to track all running processes."};
    argp_parse(&argp, argc, argv, 0, 0, &opts);

    int lock_fd;
    if(file_lock(LOCKFILE, &lock_fd) != 0) {
        return 1;
    }

    #if PRINT_HASHES
    print_hashes();
    #endif

    Tracker tracker;
    if(get_packages(tracker.packages, sizeof(tracker.packages), &tracker.packages_count) != 0) {
        fprintf(stderr, "Failed to get packages\n");
        return 1;
    }

    if(tracker.packages_count == 0) {
        fprintf(stderr, "Packages list is empty\n");
        return 1;
    }

    if(get_inits(tracker.inits, sizeof(tracker.inits), &tracker.inits_count) != 0) {
        fprintf(stderr, "Failed to get inits\n");
        return 1;
    }

    if(tracker.inits_count == 0) {
        fprintf(stderr, "Inits list is empty\n");
        return 1;
    }

#if PRINT_PACKAGES
    printf("Pacakges:\n");
    for(int i = 0; i < tracker.packages_count; i++) {
        printf("%s\n", tracker.packages[i].name);
    }

    printf("Inits:\n");
    for(int i = 0; i < tracker.inits_count; i++) {
        printf("%s\n", tracker.inits[i].name);
    }
#endif

    EmailWorker emails_worker;
    emailworker_init(&emails_worker, opts.server, opts.port, opts.email, opts.username, opts.pasword, 6);

    MessageWorker messages_worker;
    msgworker_init(&messages_worker, &emails_worker, "tracker", SEND_EMAILS, SEND_SMS, PRINT);

    ProcCheck proc_check;
    proc_check_init(&proc_check, &tracker, &messages_worker, MAX_PROCS, VALIDATE_THREADS, COMPARE_THREADS, GENERATE_MESSAGES, PRINT);
    
    DIR *procs_dir = opendir(DIR_PROC);
    if(procs_dir == NULL) {
        fprintf(stderr, "Failed to open proc directory\n");
        return 1;
    }
    long procs_dir_start = telldir(procs_dir);
#if PRINT
    printf("  %-3s %-5s %-5s %s %-32.32s %-18.18s %-32.32s %-3s %-3s %-3s %s\n","ID", "PID", "PPID", "S", "CMD", "COMM", "EXE", "SOK", "KWR", "PKG", "HASH");
#endif
    char buf[2048];

    clock_t t = clock();
    double time_taken = ((double)(clock() - t))/CLOCKS_PER_SEC;

    while(!interrupt) {
        seekdir(procs_dir, procs_dir_start);

        t = clock();
        if(proc_check_loop(&proc_check, procs_dir, buf, sizeof(buf) / sizeof(char)) != 0) {
            break;
        }
        time_taken = ((double)(clock() - t))/CLOCKS_PER_SEC;
        #if PRINT_TIME
        printf("%f %d\n", time_taken, procWorker.queue->length);
        #endif
    }

    closedir(procs_dir);
    proc_check_free(&proc_check);
    msgworker_free(&messages_worker);
    emailworker_free(&emails_worker);

    file_unlock(lock_fd);
    return 0;
}
