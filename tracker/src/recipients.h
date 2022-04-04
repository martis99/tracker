#ifndef RECIPIENTS_H
#define RECIPIENTS_H

typedef struct Recipient {
    char email[64];
    char phone[20];
    int validations;
    int changes;
    int errors;
} Recipient;

int recipients_from_uci(Recipient **precipients, const char *config_name, int *pcount);

#endif