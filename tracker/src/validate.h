#ifndef VALIDATE_H
#define VALIDATE_H

#include <stddef.h>

void print_hashes();
int hash_gen(const char *path, unsigned char *hash, size_t size);
int hash_validate(const char *exe, const char *hash);
int link_validate(const char *str, const char *exe);
int cmd_validate(const char *cmd, const char *exe);
int comm_validate(const char *comm, const char *exe);
int socket_validate(const char *exe);
int exe_validate(const char *exe);
int package_validate(const char *exe);

int cmd_change_validate(const char *a, const char *b);
int comm_change_validate(const char *a, const char *b);
int exe_change_validate(const char *a, const char *b);


#endif