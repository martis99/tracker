#ifndef PROC_CHECK_H
#define PROC_CHECK_H

#include "tracker.h"
#include "message.h"
#include "proc.h"

typedef struct IdQueue {
    int data[512];
    int start;
    int end;
    int size;
} IdQueue;

typedef struct ValidWorker {
    Queue *valid_queue;
    Tracker *tracker;
    MessageWorker *messages_worker;
    int generate_messages;
    int print;
} ValidWorker;

typedef struct CompWorker {
    Queue *comp_queue;
    Tracker *tracker;
    MessageWorker *messages_worker;
    int generate_messages;
} CompWorker;

typedef struct ProcCheck {
    IdQueue freeids;
    ValidWorker valids_worker;
    CompWorker comps_worker;
    Proc *procs;
    int max_procs;
    int procs_count;
    int validate_threads;
    int compare_threads;
    int print;
} ProcCheck;

int proc_check_loop(ProcCheck *proc_check, DIR *procs_dir, char *buf, size_t buf_len);
void proc_check_init(ProcCheck *proc_check, Tracker *tracker, MessageWorker *messages_worker, int max_procs, int validate_threads, int compare_threads, int generate_messages, int print);
void proc_check_free(ProcCheck *proc_check);

#endif