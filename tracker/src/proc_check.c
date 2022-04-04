#include "proc_check.h"

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <pthread.h>

static void valid_proc(Proc *proc, ValidWorker *valids_worker) {
    if(proc->checked == 1) {
        return;
    }

    proc_chk(proc, 1);

    if((proc->kworker == 1 && proc->rkworker == KWR_OK) || (proc->other ==  1 && proc->rother == OTH_OK)) {
        proc->remove = 1;
        proc->print = 0;
        proc->checked = 1;
    } else {
        if(valids_worker->print == 1) {
            printf("+ ");
            proc_print(proc);
        }
        if(valids_worker->generate_messages == 1) {
            queue_push_head(valids_worker->messages_worker->messages_queue, proc);
        } else {
            proc->checked = 1;
        }
    }
}

static void *valid_worker(void *arg) {
    ValidWorker *valids_worker = (ValidWorker*)arg;
    while(1) {
        Proc *proc = queue_pop_tail(valids_worker->valid_queue);
        valid_proc(proc, valids_worker);
    }
    return NULL;
}

static void comp_proc(Proc *prev, Proc *proc, CompWorker *comps_worker) {
    if(proc->checked == 1) {
        return;
    }

    proc_chk(proc, 0);

    if((proc->kworker == 1 && proc->rkworker == KWR_OK) || (proc->other ==  1 && proc->rother == OTH_OK)) {
        proc->remove = 1;
        proc->print = 0;
        proc->checked = 1;
    } else {
        if(comps_worker->generate_messages == 1) {
            msgworker_compare(comps_worker->messages_worker, prev, proc);
        }
    }
}

static void *comp_worker(void *arg) {
    CompWorker *comps_worker = (CompWorker*)arg;
    while(1) {
        Proc *proc = queue_pop_tail(comps_worker->comp_queue);
        comp_proc(NULL, proc, comps_worker);
    }
    return NULL;
}

int proc_check_loop(ProcCheck *proc_check, DIR *procs_dir, char *buf, size_t buf_len) {
    char proc_path[270];

    struct dirent *proc_dir;

    for(int i = 0; i < proc_check->procs_count; i++) {
        if(proc_check->procs[i].removed == 0) {
            proc_check->procs[i].remove = 1;
        }
    }

    while((proc_dir = readdir(procs_dir)) != NULL) {
        int pid = atoi(proc_dir->d_name);
        if(pid == 0) {
            continue;
        }

        Proc *prev = proc_get_by_pid(proc_check->procs, proc_check->procs_count, pid);
        snprintf(proc_path, sizeof(proc_path) / sizeof(char), "/proc/%s", proc_dir->d_name);
        if(dir_exists(proc_path) != 0) {
            if(prev != NULL) {
                prev->remove = 1;
            }
            continue;
        }

        if(prev == NULL) {
            int id = proc_check->freeids.end - proc_check->freeids.start != 0 ? proc_check->freeids.data[proc_check->freeids.start++ % proc_check->freeids.size] : proc_check->procs_count++;
            if(proc_check->procs_count >= proc_check->max_procs) {
                fprintf(stderr, "Max process count reached\n");
                return 1;
            }
            Proc *proc = &proc_check->procs[id];
            proc->id = id;
            proc->pid = pid;
            proc->checked = 0;
            proc->remove = 0;
            proc->removed = 0;
            proc->print = 1;
            proc_get(proc, proc_check->valids_worker.tracker, buf, buf_len);
            if(proc_check->validate_threads > 0) {
                queue_push_head(proc_check->valids_worker.valid_queue, proc);
            } else {
                valid_proc(proc, &proc_check->valids_worker);
            }
        } else {
            prev->remove = 0;
            if(prev->checked == 0) {
                continue;
            }
            Proc proc;
            proc.id = prev->id;
            proc.pid = pid;
            proc.checked = 0;
            proc.remove = 0;
            proc.removed = 0;
            proc.print = 1;
            proc_get(&proc, proc_check->comps_worker.tracker, buf, buf_len);
            if(proc_check->compare_threads > 0) {
                queue_push_head(proc_check->comps_worker.comp_queue, &proc);
            } else {
                comp_proc(prev, &proc, &proc_check->comps_worker);
            }
        }
    }

    for(int i = 0; i < proc_check->procs_count; i++) {
        if(proc_check->procs[i].removed == 0 && proc_check->procs[i].remove == 1 && proc_check->procs[i].checked == 1) {
            if(proc_check->procs[i].print == 1 && proc_check->print == 1) {
                printf("- ");
                proc_print(&proc_check->procs[i]);
                fflush(stdout);
            }
            proc_check->freeids.data[proc_check->freeids.end++ % proc_check->freeids.size] = i;
            proc_check->procs[i].removed = 1;
        }
    }

    return 0;
}

void proc_check_init(ProcCheck *proc_check, Tracker *tracker, MessageWorker *messages_worker, int max_procs, int validate_threads, int compare_threads, int generate_messages, int print) {
    proc_check->procs = malloc(max_procs * sizeof(Proc));
    proc_check->max_procs = max_procs;
    proc_check->print = print;

    proc_check->validate_threads = validate_threads;
    proc_check->compare_threads = compare_threads;

    proc_check->freeids.start = 0;
    proc_check->freeids.end = 0;
    proc_check->freeids.size = sizeof(proc_check->freeids.data) / sizeof(int);

    proc_check->valids_worker.tracker = tracker;
    proc_check->valids_worker.valid_queue = queue_new(200);
    proc_check->valids_worker.messages_worker = messages_worker;
    proc_check->valids_worker.generate_messages = generate_messages;
    proc_check->valids_worker.print = print;

    proc_check->comps_worker.tracker = tracker;
    proc_check->comps_worker.comp_queue = queue_new(200);
    proc_check->comps_worker.messages_worker = messages_worker;
    proc_check->comps_worker.generate_messages = generate_messages;

    pthread_t thread;
    for(int i = 0; i < validate_threads; i++) {
        pthread_create(&thread, NULL, valid_worker, &proc_check->valids_worker);
        pthread_detach(thread);
    }
    for(int i = 0; i < compare_threads; i++) {
        pthread_create(&thread, NULL, comp_worker, &proc_check->comps_worker);
        pthread_detach(thread);
    }
}

void proc_check_free(ProcCheck *proc_check) {
    free(proc_check->valids_worker.valid_queue);
    free(proc_check->comps_worker.comp_queue);
}