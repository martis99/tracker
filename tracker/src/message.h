#ifndef MESSAGE_H
#define MESSAGE_H

#include "proc.h"
#include "email.h"
#include "recipients.h"
#include "queue.h"

#include <stddef.h>

typedef struct MessageWorker {
    Queue *messages_queue;
    EmailWorker *emails_worker;
    Recipient *recipients;
    int recipients_count;
    int send_email;
    int send_sms;
    int print;
} MessageWorker;

void msgworker_compare(MessageWorker *messages_worker, Proc *a, Proc *b);

void msgworker_init(MessageWorker *messages_worker, EmailWorker *emails_worker, const char *recipients_config_name, int send_email, int send_sms, int print);
void msgworker_free(MessageWorker *messages_worker);
#endif