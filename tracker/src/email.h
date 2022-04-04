#ifndef EMAIL_H
#define EMAIL_H

#include "queue.h"

#include <curl/curl.h>

typedef struct Email {
    const char *recipient;
    const char *subject;
    char message[2048];
} Email;

typedef struct EmailWorker {
    CURL *curl;
    const char *sender_email;
    Queue *emails_queue;
} EmailWorker;

void emailworker_init(EmailWorker *emails_worker, const char *smtp_server, long smtp_port, const char *sender_email, const char *username, const char *password, unsigned int max_size);
void emailworker_push(EmailWorker *emails_worker, Email *email);
void emailworker_free(EmailWorker *emails_worker);
#endif