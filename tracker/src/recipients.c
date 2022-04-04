#include "recipients.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <memory.h>
#include <uci.h>

static int parse_enabled(const char *value) {
    if(strcmp(value, "1") == 0) {
        return 1;
    } else {
        return 0;
    }
}

static int parse_recipient(Recipient *recipient, struct uci_option *option) {
    if(option->type == UCI_TYPE_STRING) {
        if(strcmp(option->e.name, "email") == 0) {
            memcpy(recipient->email, option->v.string, strlen(option->v.string) + 1);
        } else if(strcmp(option->e.name, "phone") == 0) {
            memcpy(recipient->phone, option->v.string, strlen(option->v.string) + 1);
        } else if(strcmp(option->e.name, "validations") == 0) {
            recipient->validations = parse_enabled(option->v.string);
        } else if(strcmp(option->e.name, "changes") == 0) {
            recipient->changes = parse_enabled(option->v.string);
        } else if(strcmp(option->e.name, "errors") == 0) {
            recipient->errors = parse_enabled(option->v.string);
        } else {
            fprintf(stderr, "Warning: Unknown option '%s'. Skipping...\n", option->e.name);
            return 1;
        }
    } else {
        fprintf(stderr, "Warning: All recipient options must be strings. Skipping...\n");
        return 1;
    }
    return 0;
}

int recipients_from_uci(Recipient **precipients, const char *config_name, int *pcount) {
    struct uci_context *context = uci_alloc_context();
	struct uci_package *package;

	if(uci_load(context, config_name, &package) != UCI_OK) {
		uci_perror(context, "uci_load()");
		uci_free_context(context);
		return 1;
	}

    int count = 0;
	struct uci_element *i, *j;
	uci_foreach_element(&package->sections, i) {
		struct uci_section *section = uci_to_section(i);
		if(strcmp(section->type, "recipient") == 0) {
			count++;
		}
	}

    Recipient *recipients = malloc(count * sizeof(Recipient));
    count = 0;
	uci_foreach_element(&package->sections, i) {
		struct uci_section *section = uci_to_section(i);
		if(strcmp(section->type, "recipient") == 0) {
			uci_foreach_element(&section->options, j) {
                struct uci_option *option = uci_to_option(j);
                parse_recipient(&recipients[count], option);
			}
            count++;
		}
    }

    if(precipients != NULL) {
        *precipients = recipients;
    }
    if(pcount != NULL) {
        *pcount = count;
    }

	uci_free_context(context);
    return 0;
}