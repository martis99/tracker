#include "message.h"

#include "recipients.h"
#include "validate.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void generate_validation_message(Proc *proc, char *msg, size_t max_len, size_t *plen, int errors, int validations) {
    size_t len = 0;

    if(errors == 1) {
        if(proc->rpid == PID_FAILED_TO_READ) {
            len += snprintf(msg + len, max_len -len, "Failed to read process pid\n");
        }
        if(proc->rexe == EXE_FAILED_TO_GET_PATH) {
            len += snprintf(msg + len, max_len - len, "Failed to generate process exe path\n");
        }

        if(proc->rcmd == CMD_FAILED_TO_GET_PATH) {
            len += snprintf(msg + len, max_len - len, "Failed to generate process cmd path\n");
        } else if(proc->rcmd == CMD_FAILED_TO_READ) {
            len += snprintf(msg + len, max_len - len, "Failed to read process cmd file\n");
        }

        if(proc->rcomm == COMM_FAILED_TO_GET_PATH) {
            len += snprintf(msg + len, max_len - len, "Failed to generate process comm path\n");
        } else if(proc->rcomm == COMM_FAILED_TO_READ) {
            len += snprintf(msg + len, max_len - len, "Failed to read process comm file\n");
        }

        if(proc->rstat == STAT_FAILED_TO_GET_PATH) {
            len += snprintf(msg + len, max_len - len, "Failed to generate process stat path\n");
        } else if(proc->rstat == STAT_FAILED_TO_READ) {
            len += snprintf(msg + len, max_len - len, "Failed to read process stat file\n");
        } else if(proc->rstat == STAT_FAILED_TO_PARSE) {
            len += snprintf(msg + len, max_len - len, "Failed to parse process stat file\n");
        }

        if(proc->rhash == HASH_FAILED_TO_GENERATE) {
            len += snprintf(msg + len, max_len - len, "Failed to generate process exe hash\n");
        }

        if(proc->rsocket == SKT_FAILED_TO_GET_PATH) {
            len += snprintf(msg + len, max_len - len, "Failed to generate process fd path\n");
        } else if(proc->rsocket == SKT_FAILED_TO_READ) {
            len += snprintf(msg + len, max_len - len, "Failed to read process fd file\n");
        }
    }

    if(validations == 1) {
        if(proc->rstat == STAT_OK && proc->rpid == PID_DO_NOT_MATCH) {
            len += snprintf(msg + len, max_len - len, "Process pids '%d' and '%d' do no match\n", proc->pid, proc->stat.pid);
        }

        if(proc->rexe == EXE_OK) {
            if(proc->rcmd == CMD_INVALID) {
                len += snprintf(msg + len, max_len - len, "Process cmd '%s' is invalid\n", proc->cmd);
            }

            if(proc->rcomm == COMM_INVALID) {
                len += snprintf(msg + len, max_len - len, "Process comm '%s' is invalid\n", proc->comm);
            }
            
            if(proc->rhash == HASH_INVALID) {
                len += snprintf(msg + len, max_len - len, "Process hash is invalid\n");
            }
        } else if(proc->rexe == EXE_NOT_IN_PATH) {
            len += snprintf(msg + len, max_len - len, "Process exe '%s' is not in path\n", proc->exe);
        } else if(proc->rexe == EXE_DELETED) {
            len += snprintf(msg + len, max_len - len, "Process exe '%s' is deleted\n", proc->exe);
        }

        if(proc->rsocket == SKT_USING_WITHOUT_PERMISSION) {
            len += snprintf(msg + len, max_len - len, "Process is using socket without permission\n");
        }
        if(proc->rpackage == PKG_NOT_IN_LIST) {
            len += snprintf(msg + len, max_len - len, "Process is not in the list of installed applications\n");
        }
    }

    if(len > 0) {
        len += snprintf(msg + len, max_len - len, "Pid: %d\nBin: %s\nCmd: %s\n", proc->pid, proc->exe, proc->cmd);
    }

    if(plen != NULL) {
        *plen = len;
    }
}

static void generate_change_message(Proc *a, Proc *b, char *msg, size_t max_len, size_t *plen, int errors, int changes) {
    int len = 0;

    if(errors == 1) {
        if(b->pid == 0) {
            len += snprintf(msg + len, max_len - len, "Failed to get process pid\n");
        }
        if(strlen(b->cmd) == 0) {
            len += snprintf(msg + len, max_len - len, "Failed to get process cmd\n");
        }
        if(strlen(b->comm) == 0) {
            len += snprintf(msg + len, max_len - len, "Failed to get process comm\n");
        }
        if(strlen(b->exe) == 0) {
            len += snprintf(msg + len, max_len - len, "Failed to get process exe\n");
        }
    }

    if(changes == 1) {
        if(a->pid != b->pid) {
            len += snprintf(msg + len, max_len - len, "Process pid has changed from '%d' to '%d'\n", a->pid, b->pid);
        }

        if(a->stat.ppid != a->stat.ppid) {
            len += snprintf(msg + len, max_len - len, "Process ppid has changed from '%d' to '%d'\n", a->stat.ppid, b->stat.ppid);
        }

        if(strlen(b->cmd) > 0 && strcmp(a->cmd, b->cmd) != 0) {
            if(strncmp(a->cmd, "luci-bwc ", 9) == 0 && strncmp(b->cmd, "luci-bwc ", 9) == 0 ) {

            } else {
                if(cmd_change_validate(a->cmd, b->cmd) != 0) {
                    len += snprintf(msg + len, max_len - len, "Process cmd has changed from '%s' to '%s'\n", a->cmd, b->cmd);
                }
            }
        }

        if(strlen(b->comm) > 0 && strcmp(a->comm, b->comm) != 0 && comm_change_validate(a->comm, b->comm) != 0) {
            len += snprintf(msg + len, max_len - len, "Process comm has changed from '%s' to '%s'\n", a->comm, b->comm);
        }

        if(strlen(b->exe) > 0 && strcmp(a->exe, b->exe) != 0 && exe_change_validate(a->exe, b->exe) != 0) {
            len += snprintf(msg + len, max_len - len, "Process exe has changed from '%s' to '%s'\n", a->exe, b->exe);
        }
    }

    if(len > 0) {
        len += snprintf(msg + len, max_len - len, "Pid: %d\nBin: %s\nCmd: %s\n", b->pid, b->exe, b->cmd);
    }

    if(plen != NULL) {
        *plen = len;
    }
}

static void send_sms(const char *phone, const char *msg, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "gsmctl -S -s \"%s %s\"", phone, msg);
    FILE *fp = popen(buf, "r");
    if(fp == NULL) {
        fprintf(stderr, "Failed to send SMS to %s\n", phone);
    } else {
        const char *r = fgets(buf, buf_len, fp);
        if(r == NULL) {
            fprintf(stderr, "Failed to send SMS to %s\n", phone);
        } else {
            if(strcmp(r, "OK\n") != 0) {
                fprintf(stderr, "Failed to send SMS to %s: %s", phone, r);
            }
        }
        pclose(fp);
    }
}

static void *message_worker(void *arg) {
    MessageWorker *messages_worker = (MessageWorker*)arg;
    char buf[1024];
    while(1) {
        Proc *proc = queue_pop_tail(messages_worker->messages_queue);
        Email *email = malloc(sizeof(Email));
        size_t len = 0;
        generate_validation_message(proc, email->message, sizeof(email->message) / sizeof(char), &len, 0, 1);
        if(len > 0) {
            fprintf(stdout, "%s", email->message);
            for(int i = 0; i < messages_worker->recipients_count; i++) {
                email->recipient = messages_worker->recipients[i].email;
                email->subject = "Tracker report";

                generate_validation_message(proc, email->message, sizeof(email->message) / sizeof(char), &len, messages_worker->recipients[i].errors, messages_worker->recipients[i].validations);
                if(len > 0) {
                    if(messages_worker->send_sms == 1) {
                        if(strlen(messages_worker->recipients[i].phone) > 0) {
                            send_sms(messages_worker->recipients[i].phone, email->message, buf, sizeof(buf) / sizeof(char));
                        }
                    }
                    if(messages_worker->send_email == 1) {
                        if(strlen(messages_worker->recipients[i].email) > 0) {
                            emailworker_push(messages_worker->emails_worker, email);
                            email = malloc(sizeof(Email));
                        }
                    }
                }
            }
            fflush(stdout);
        }

        free(email);
        
        proc->checked = 1;
    }
}

void msgworker_compare(MessageWorker *messages_worker, Proc *a, Proc *b) {
    Email *email = malloc(sizeof(Email));
    size_t len = 0;
    char buf[1024];

    generate_change_message(a, b, email->message, sizeof(email->message) / sizeof(char), &len, 0, 1);

    if(len > 0) {
        if(messages_worker->print == 1) {
            printf("* ");
            proc_print(a);
            printf("->");
            proc_print(b);
        }
        fprintf(stdout, "%s", email->message);

        for(int i = 0; i < messages_worker->recipients_count; i++) {
            email->recipient = messages_worker->recipients[i].email;
            email->subject = "Tracker report";

            generate_change_message(a, b, email->message, sizeof(email->message) / sizeof(char), &len, messages_worker->recipients[i].errors, messages_worker->recipients[i].changes);
            if(len > 0) {
                if(messages_worker->send_sms == 1) {
                    if(strlen(messages_worker->recipients[i].phone) > 0) {
                        send_sms(messages_worker->recipients[i].phone, email->message, buf, sizeof(buf) / sizeof(char));
                    }
                }
                if(messages_worker->send_email == 1) {
                    emailworker_push(messages_worker->emails_worker, email);
                    email = malloc(sizeof(Email));
                }
            }
        }

        fflush(stdout);
        b->checked = 1;
        *a = *b;
    }

    free(email);
}

void msgworker_init(MessageWorker *messages_worker, EmailWorker *emails_worker, const char *recipients_config_name, int send_email, int send_sms, int print) {
    messages_worker->messages_queue = queue_new(100);
    messages_worker->send_email = send_email;
    messages_worker->send_sms = send_sms;
    messages_worker->emails_worker = emails_worker;
    messages_worker->print = print;
    recipients_from_uci(&messages_worker->recipients, recipients_config_name, &messages_worker->recipients_count);

    pthread_t thread;
    pthread_create(&thread, NULL, message_worker, messages_worker);
    pthread_detach(thread);
}

void msgworker_free(MessageWorker *messages_worker) {
    free(messages_worker->messages_queue);
    free(messages_worker->recipients);
}