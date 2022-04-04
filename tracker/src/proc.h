#ifndef PROC_H
#define PROC_H

#include "tracker.h"
#include "utils.h"

#include <limits.h>
#include <openssl/sha.h>

#define DIR_PROC "/proc"

typedef enum PIDCode {
    PID_UNKNOWN,
    PID_OK,
    PID_DO_NOT_MATCH,
    PID_FAILED_TO_READ
} PIDCode;

typedef enum STATCode {
    STAT_UNKNOWN,
    STAT_OK,
    STAT_FAILED_TO_GET_PATH,
    STAT_FAILED_TO_READ,
    STAT_FAILED_TO_PARSE
} STATCode;

typedef enum CMDCode {
    CMD_UNKNOWN,
    CMD_OK,
    CMD_EMPTY,
    CMD_INVALID,
    CMD_FAILED_TO_GET_PATH,
    CMD_FAILED_TO_READ
} CMDCode;

typedef enum COMMCode {
    COMM_UNKNOWN,
    COMM_OK,
    COMM_EMPTY,
    COMM_INVALID,
    COMM_FAILED_TO_GET_PATH,
    COMM_FAILED_TO_READ
} COMMCode;

typedef enum EXECode {
    EXE_UNKNOWN,
    EXE_OK,
    EXE_NOT_IN_PATH,
    EXE_DELETED,
    EXE_FAILED_TO_GET_PATH
} EXECode;

typedef enum SKTCode {
    SKT_UNKNOWN,
    SKT_OK,
    SKT_USING_WITHOUT_PERMISSION,
    SKT_FAILED_TO_GET_PATH,
    SKT_FAILED_TO_READ
} SKTCode;

typedef enum KWRCode {
    KWR_UNKNOWN,
    KWR_OK,
    KWR_WARNING
} KWRCode;

typedef enum OTHCode {
    OTH_UNKNOWN,
    OTH_OK,
    OTH_WARNING
} OTHCode;

typedef enum PKGCode {
    PKG_UNKNOWN,
    PKG_OK,
    PKG_NOT_IN_LIST
} PKGCode;

typedef enum HASHCode {
    HASH_UNKNOWN,
    HASH_OK,
    HASH_INVALID,
    HASH_FAILED_TO_GENERATE
} HASHCode;

typedef struct ProcStat {
    int pid;
    char comm[32];
    char state;
    int ppid;
} ProcStat;

typedef struct Proc Proc;
struct Proc {
    int id;
    int pid;
    ProcStat stat;
    char cmd[2048];
    char comm[32];
    char exe[PATH_MAX];
    int using_socket;
    int kworker;
    int other;
    int in_package;
    unsigned char hash[SHA_DIGEST_LENGTH * 2 + 1];
    int rpid;
    int rppid;
    int rstate;
    STATCode rstat;
    CMDCode rcmd;
    COMMCode rcomm;
    EXECode rexe;
    SKTCode rsocket;
    KWRCode rkworker;
    OTHCode rother;
    PKGCode rpackage;
    HASHCode rhash;
    int checked;
    int remove;
    int removed;
    int print;
    int is_new;
    Proc *new_proc;
};

void proc_get(Proc *proc, Tracker *tracker, char *buf, size_t buf_len);
void proc_chk(Proc *proc, int gen_hash);

Proc *proc_get_by_pid(Proc *procs, int count, int pid);
void proc_print(const Proc *proc);

#endif