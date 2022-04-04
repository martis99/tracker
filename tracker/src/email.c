#include "email.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct upload_data {
    char payload[512];
    int bytes_read;
};

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
    struct upload_data *upload_ctx = (struct upload_data*)userp;
    const char * data;
    size_t room = size * nmemb;
    if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
        return 0;
    }

    data = &upload_ctx->payload[upload_ctx->bytes_read];
    if(data != NULL) {
        size_t len = strlen(data);
        if(room < len) {
            len = room;
        }
        memcpy(ptr, data, len);
        upload_ctx->bytes_read += len;

        return len;
    }

    return 0;
}

int send_email(EmailWorker *emails_worker, Email *email) {
    CURLcode res = CURLE_OK;
    struct curl_slist *recipients = NULL;
    struct upload_data upload_ctx;
    snprintf(upload_ctx.payload, sizeof(upload_ctx) / sizeof(char), "From: Tracker %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", emails_worker->sender_email, email->recipient, email->subject, email->message);
    upload_ctx.bytes_read = 0;

    recipients = curl_slist_append(recipients, email->recipient);
    curl_easy_setopt(emails_worker->curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(emails_worker->curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(emails_worker->curl, CURLOPT_UPLOAD, 1L);

    res = curl_easy_perform(emails_worker->curl);
    if(res != CURLE_OK) {
        fprintf(stderr, "Failed to send email: %s\n", curl_easy_strerror(res));
        return 0;
    }

    curl_slist_free_all(recipients);
    return 1;
}

static void *email_worker(void *arg) {
    EmailWorker *emails_worker = (EmailWorker*) arg;
    while(1) {
        Email *email = queue_pop_tail(emails_worker->emails_queue);
        send_email(emails_worker, email);
        free(email);
    }
    return NULL;
}

void emailworker_init(EmailWorker *emails_worker, const char *smtp_server, long smtp_port, const char *sender_email, const char *username, const char *password, unsigned int max_size) {
    emails_worker->curl = curl_easy_init();
    emails_worker->sender_email = sender_email;

    curl_easy_setopt(emails_worker->curl, CURLOPT_URL, smtp_server);
    curl_easy_setopt(emails_worker->curl, CURLOPT_PORT, smtp_port);
    curl_easy_setopt(emails_worker->curl, CURLOPT_MAIL_FROM, sender_email);
    curl_easy_setopt(emails_worker->curl, CURLOPT_USERNAME, username);
    curl_easy_setopt(emails_worker->curl, CURLOPT_PASSWORD, password);
    curl_easy_setopt(emails_worker->curl, CURLOPT_READFUNCTION, payload_source);

    emails_worker->emails_queue = queue_new(max_size);
    pthread_t thread;
    pthread_create(&thread, NULL, email_worker, emails_worker);
    pthread_detach(thread);
}

void emailworker_push(EmailWorker *emails_worker, Email *email) {
    queue_push_head(emails_worker->emails_queue, email);
}

void emailworker_free(EmailWorker *emails_worker) {
    curl_easy_cleanup(emails_worker->curl);
    free(emails_worker->emails_queue);
}