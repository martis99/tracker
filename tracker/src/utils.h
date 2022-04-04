#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <dirent.h>

#define WHITESPACES " \t\n\r\f\v"

typedef struct Str {
    char name[64];
    size_t len;
} Str;

int read_from_file(const char *path, char *str, size_t size);
void red();
void green();
void yellow();
void white();
void paint(int r);
const char *get_filename(const char *str);
int is_filename(const char *str, const char *exe, int full);
int filename_same(const char *str, const char *exe);
int get_packages(Str *packages, size_t packages_size, int *count);
int get_inits(Str *inits, size_t inits_size, int *count);

typedef int (*loop_callback) (struct dirent *dire, void *data);
int loop_dir(const char *path, loop_callback callback, void *data);
int str_cmp(const char *a, const Str *b);
int str_in_list(const Str *strs, size_t strs_count, const char *str);
int dir_exists(const char *path);

#endif