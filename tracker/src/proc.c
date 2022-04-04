#include "proc.h"
#include "utils.h"

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "validate.h"

#define DIR_STAT "/proc/%d/stat"
#define DIR_CMD "/proc/%d/cmdline"
#define DIR_COMM "/proc/%d/comm"
#define DIR_EXE "/proc/%d/exe"
#define DIR_FD "/proc/%d/fd"

static STATCode get_stat(char *buf, size_t buf_len, int pid, ProcStat *stat) {
    if(snprintf(buf, buf_len, DIR_STAT, pid) < 0) {
        return STAT_FAILED_TO_GET_PATH;
    }

    FILE *fp = fopen(buf, "r");
    if(fp == NULL) {
        return STAT_FAILED_TO_READ;
    }
    
    if(fscanf(fp, "%d (%[^\t\n)]) %c %d", &stat->pid, stat->comm, &stat->state, &stat->ppid) != 4) {
        fclose(fp);
        return STAT_FAILED_TO_PARSE;
    }
    fclose(fp);
    return STAT_UNKNOWN;
}

static CMDCode get_cmd(char *buf, size_t buf_len, int pid, char *cmd, size_t cmd_size) {
    if(snprintf(buf, buf_len, DIR_CMD, pid) <= 0) {
        return CMD_FAILED_TO_GET_PATH;
    }

    if(read_from_file(buf, cmd, cmd_size) != 0) {
        return CMD_FAILED_TO_READ;
    }

    return CMD_UNKNOWN;
}

static COMMCode get_comm(char *buf, size_t buf_len, int pid, char *comm, size_t comm_size) {
    if(snprintf(buf, buf_len, DIR_COMM, pid) < 0) {
        return COMM_FAILED_TO_GET_PATH;
    }

    if(read_from_file(buf, comm, comm_size) != 0) {
        return COMM_FAILED_TO_READ;
    }

    return COMM_UNKNOWN;
}

static EXECode get_exe(char *buf, size_t buf_len, int pid, char *exe, size_t exe_size) {
    memset(exe, 0, exe_size);
    if(snprintf(buf, buf_len, DIR_EXE, pid) < 0) {
        return EXE_FAILED_TO_GET_PATH;
    }

    size_t len = readlink(buf, exe, exe_size);
    if(len < 0) {
        memset(exe, 0, exe_size);
    } else {
        exe[len] = '\0';
    }
    
    return EXE_UNKNOWN;
}

typedef struct LoopFDData {
    char *buf;
    char tmp[512];
    char tmp2[512];
    int *using_socket;
    int pid;
} LoopFDData;

static int loop_fd(struct dirent *dire, void *pdata) {
    LoopFDData *data = (LoopFDData*)pdata;
    
    snprintf(data->tmp, sizeof(data->tmp) / sizeof(char), "%s/%s", data->buf, dire->d_name);
    if(readlink(data->tmp, data->tmp2, sizeof(data->tmp2)) < 0) {
        return 0;
    }

    if(strstr(data->tmp2, "socket") != 0) {
        *data->using_socket = 1;
        return 1;
    }

    return 0;
}

static SKTCode get_using_socket(char *buf, size_t buf_len, int pid, int *using_socket) {
    if(snprintf(buf, buf_len, DIR_FD, pid) < 0) {
        return SKT_FAILED_TO_GET_PATH;
    }

    *using_socket = 0;
    LoopFDData data;
    data.buf = buf;
    data.using_socket = using_socket;
    data.pid = pid;
    
    if(loop_dir(buf, loop_fd, &data) != 0 ) {
        return SKT_FAILED_TO_READ;
    }

    return SKT_UNKNOWN;
}

static KWRCode get_kworker(const char *comm, int *kworker) {
    unsigned int cpu;
    int id;
    char priority[64];
    if(
        sscanf(comm, "kworker/%u:%d", &cpu, &id) == 2 || sscanf(comm, "kworker/u%u:%d", &cpu, &id) == 2 ||
        sscanf(comm, "kworker/%u:%d%s", &cpu, &id, priority) == 3 || sscanf(comm, "kworker/u%u:%d%s", &cpu, &id, priority) == 3
    ) {
        *kworker = 1;
        return KWR_UNKNOWN;
    }

    *kworker = 0;
    return KWR_UNKNOWN;
}

static OTHCode get_other(int kworker, const char *cmd, const char *exe, int *other) {
    if(kworker == 1) {
        *other = 0;
        return OTH_UNKNOWN;
    }

    if(strlen(cmd) != 0) {
        *other = 0;
        return OTH_UNKNOWN;
    }

    if(strlen(exe) != 0) {
        *other = 0;
        return OTH_UNKNOWN;
    }

    *other = 1;
    return OTH_UNKNOWN;
}

static int name_in_list(const Str *list, int list_count, const char *comm, const char *cmd, const char *exe) {
    if(str_in_list(list, list_count, comm) == 0) {
        return 0;
    }

    if(strlen(cmd) > 0 && str_in_list(list, list_count, cmd) == 0) {
        return 0;
    }

    if(strlen(exe) > 0) {
        const char *exe_filename = get_filename(exe);
        if(str_in_list(list, list_count, exe_filename) == 0) {
            return 0;
        }
    }

    return 1;
}

static PKGCode get_in_package(Tracker *tracker, const char *cmd, const char *comm, const char *exe, int kworker, int *in_package) {
    *in_package = 0;
    
    if(kworker == 1) {
        return PKG_UNKNOWN;
    }
    
    if(name_in_list(tracker->packages, tracker->packages_count, comm, cmd, exe) == 0) {
        *in_package = 1;
        return PKG_UNKNOWN;
    }

    if(name_in_list(tracker->inits, tracker->inits_count, comm, cmd, exe) == 0) {
        *in_package = 1;
        return PKG_UNKNOWN;
    }
    return PKG_UNKNOWN;
}

static HASHCode get_hash(const char *exe, char *hash, size_t hash_size, EXECode rexe) {
    memset(hash, 0, hash_size);

    if(rexe != EXE_OK) {
        return HASH_UNKNOWN;
    }
 
    if(strlen(exe) == 0) {
        return HASH_UNKNOWN;
    }

#if 1
    if(hash_gen(exe, hash, hash_size) != 0) {
        return HASH_FAILED_TO_GENERATE;
    }
#else
    memset(hash, 0, hash_size);
#endif
    return HASH_UNKNOWN;
}

void proc_get(Proc *proc, Tracker *tracker, char *buf, size_t buf_len) {
    proc->rpid = PID_UNKNOWN;
    proc->rexe = get_exe(buf, buf_len, proc->pid, proc->exe, sizeof(proc->exe));
    proc->rstat = get_stat(buf, buf_len, proc->pid, &proc->stat);
    proc->rcmd = get_cmd(buf, buf_len, proc->pid, proc->cmd, sizeof(proc->cmd));
    proc->rcomm = get_comm(buf, buf_len, proc->pid, proc->comm, sizeof(proc->comm));
    proc->rsocket = get_using_socket(buf, buf_len, proc->pid, &proc->using_socket);
    proc->rkworker = get_kworker(proc->comm, &proc->kworker);
    proc->rother = get_other(proc->kworker, proc->cmd, proc->exe, &proc->other);
    proc->rpackage = get_in_package(tracker, proc->cmd, proc->comm, proc->exe, proc->kworker, &proc->in_package);
}

static PIDCode check_pid(int pid, int statpid, PIDCode rpid, STATCode rstat) {
    if(rpid != PID_UNKNOWN) {
        return rpid;
    }

    if(rstat != STAT_UNKNOWN) {
        return PID_UNKNOWN;
    }

    if(pid != statpid){
        return PID_DO_NOT_MATCH;
    }

    return PID_OK;
}

static CMDCode check_cmd(const char *cmd, const char *exe, CMDCode rcmd) {
    if(rcmd != CMD_UNKNOWN) {
        return rcmd;
    }

    if(strlen(exe) == 0) {
        return strlen(cmd) == 0 ? CMD_EMPTY : CMD_UNKNOWN;
    }

    if(strncmp(exe, cmd, strlen(exe)) == 0) {
        return CMD_OK;
    }

    if(is_filename(cmd, exe, 1) == 0) {
        return CMD_OK;
    }

    if(cmd_validate(cmd, exe) == 0) {
        return CMD_OK;
    }

    if(link_validate(cmd, exe) == 0) {
        return CMD_OK;
    }

    return CMD_INVALID;
}

static COMMCode check_comm(const char *comm, const char *exe, int kworker, int ppid, COMMCode rcomm) {
    if(rcomm != COMM_UNKNOWN) {
        return rcomm;
    }

    if(kworker == 1) {
        return COMM_UNKNOWN;
    }
    
    if(strlen(exe) == 0) {
        return strlen(comm) == 0 ? COMM_EMPTY : COMM_UNKNOWN;
    }

    if(is_filename(comm, exe, 0) == 0) {
        return COMM_OK;
    }

    if(filename_same(comm, exe) == 0) {
        return COMM_OK;
    }

    if(link_validate(comm, exe) == 0) {
        return COMM_OK;
    }

    if(comm_validate(comm, exe) == 0) {
        return COMM_OK;
    }

    return COMM_INVALID;
}

static EXECode check_exe(const char *exe, EXECode rexe) {
    if(rexe != EXE_UNKNOWN) {
        return rexe;
    }

    if(strlen(exe) == 0) {
        return EXE_UNKNOWN;
    }

    if(strstr(exe, "(deleted)") != NULL) {
        return EXE_DELETED;
    }

    if(exe_validate(exe) != 0) {
        return EXE_NOT_IN_PATH;
    }

    return EXE_OK;
}

static SKTCode check_socket(const char *exe, int using_socket, SKTCode rsocket) {
    if(rsocket != SKT_UNKNOWN) {
        return rsocket;
    }

    if(using_socket == 0) {
        return SKT_OK;
    }

    if(socket_validate(exe) == 0) {
        return SKT_OK;
    }

    return SKT_USING_WITHOUT_PERMISSION;
}

static KWRCode check_kworker(const char *cmd, const char *comm, const char *exe, int kworker, KWRCode rkworker) {
    if(rkworker != KWR_UNKNOWN) {
        return rkworker;
    }

    if(strlen(comm) == 0) {
        return KWR_UNKNOWN;
    }

    if(kworker == 0) {
        return KWR_OK;
    }
    
    if(strlen(cmd) != 0) {
        return KWR_WARNING;
    }

    if(strlen(exe) != 0) {
        return KWR_WARNING;
    }

    return KWR_OK;
}

static OTHCode check_other(const char *cmd, const char *comm, const char *exe, int other, OTHCode rother) {
     if(rother != OTH_UNKNOWN) {
        return rother;
    }

    if(strlen(comm) == 0) {
        return OTH_UNKNOWN;
    }

    if(other == 0) {
        return OTH_OK;
    }
    
    if(strlen(cmd) != 0) {
        return OTH_WARNING;
    }

    if(strlen(exe) != 0) {
        return OTH_WARNING;
    }

    return OTH_OK;
}

static PKGCode check_package(int package, int kworker, const char *exe, PKGCode rpackage) {
    if(rpackage != PKG_UNKNOWN) {
        return rpackage;
    }

    if(strlen(exe) == 0) {
        return PKG_UNKNOWN;
    }

    if(package == 1) {
        return PKG_OK;
    }

    if(kworker == 1) {
        return PKG_OK;
    }

    if(package_validate(exe) != 0) {
        return PKG_NOT_IN_LIST;
    }

    return PKG_OK;
}

static HASHCode check_hash(const char *exe, const char *hash, const char *comm, HASHCode rhash) {
    if(rhash != HASH_UNKNOWN) {
        return rhash;
    }

    if(strlen(exe) == 0) {
        return HASH_UNKNOWN;
    }

    if(strlen(hash) == 0) {
        return HASH_UNKNOWN;
    }
    
    if(hash_validate(exe, hash) == 0) {
        return HASH_OK;
    }

    if(strcmp(exe, "/usr/bin/tracker") == 0 && strcmp(comm, "tracker") == 0) {
        return HASH_OK;
    }

    return HASH_INVALID;
}

void proc_chk(Proc *proc, int gen_hash) {   
    proc->rpid = check_pid(proc->pid, proc->stat.pid, proc->rpid, proc->rstat);
    proc->rppid = 0;
    proc->rstate = 0;
    proc->rcmd = check_cmd(proc->cmd, proc->exe, proc->rcmd);
    proc->rcomm = check_comm(proc->stat.comm, proc->exe, proc->kworker, proc->stat.ppid, proc->rcomm);
    proc->rexe = check_exe(proc->exe, proc->rexe);
    proc->rsocket = check_socket(proc->exe, proc->using_socket, proc->rsocket);
    proc->rkworker = check_kworker(proc->cmd, proc->comm, proc->exe, proc->kworker, proc->rkworker);
    proc->rother = check_other(proc->cmd, proc->comm, proc->exe, proc->other, proc->rother);
    proc->rpackage = check_package(proc->in_package, proc->kworker, proc->exe, proc->rpackage);
    if(gen_hash == 1) {
        proc->rhash = get_hash(proc->exe, proc->hash, sizeof(proc->hash), proc->rexe);
        proc->rhash = check_hash(proc->exe, proc->hash, proc->comm, proc->rhash);
    } else {
        memset(proc->hash, 0, sizeof(proc->hash));
    }
}

Proc *proc_get_by_pid(Proc *procs, int count, int pid) {
    for(int i = 0; i < count; i++) {
        if(procs[i].removed == 0 && procs[i].pid == pid) {
            return &procs[i];
        }
    }
    return NULL;
}

void proc_print(const Proc *proc) {
    paint(0);
    printf("%-3i ", proc->id);
    paint(proc->rpid);
    printf("%-5i ", proc->pid);
    paint(proc->rppid);
    printf("%-5i ", proc->stat.ppid);
    paint(proc->rstate);
    printf("%c ", proc->stat.state);
    paint(proc->rcmd);
    printf("%-32.32s ", proc->cmd);
    paint(proc->rcomm);
    printf("%-18.18s ", proc->comm);
    paint(proc->rexe);
    printf("%-32.32s ", proc->exe);
    paint(proc->rsocket);
    printf("%-3s ", proc->using_socket == 1 ? "yes" : "no");
    paint(proc->kworker * proc->rkworker);
    printf("%-3s ", proc->kworker == 1 ? "yes" : "no");
    /*paint(0);
    printf("%-3s ", proc->other == 1 ? "yes" : "no");*/
    paint(proc->rpackage);
    printf("%-3s ", proc->in_package == 1 ? "yes" : "no");
    paint(proc->rhash);
    printf("%.*s ", (int)(sizeof(proc->hash)/sizeof(unsigned char)), proc->hash);
    paint(0);
    printf("\n");
}