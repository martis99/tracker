#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

static char *rtrim(char *s, size_t n, const char *characters) {
    char *r = s, * end;
    size_t len = strlen(s) - 1;
    len = n < len ? n : len;
    for (end = s+len; strstr(characters, r+len) && end != s; end = s+len, *(r + (len--)) = 0);
    return r;
}

int read_from_file(const char *path, char *str, size_t size) {
    memset(str, 0, size);
    FILE *fp = fopen(path, "r");
    if(fp == NULL) {
        return 1;
    }
    fgets(str, size, fp);
    rtrim(str, size / sizeof(char), WHITESPACES);
    fclose(fp);
    return 0;
}

void red() {
  printf("\033[0;31m");
}

void green() {
  printf("\033[0;32m");
}

void yellow() {
  printf("\033[0;93m");
}

void white() {
  printf("\033[0m");
}

void paint(int r) {
    switch(r) {
    case 0:
        white();
        break;
    case 1:
        green();
        break;
    default:
        yellow();
        break;
    }
}

const char *get_filename(const char *str){
    const char *filename = strrchr(str, '/');
    return filename == NULL ? str : filename + 1; 
}

int is_filename(const char *str, const char *exe, int full) {
    const char *filename = get_filename(exe);
    int len = exe + strlen(exe) - filename;
    if(full == 1) {
        if(strncmp(filename, str, len) == 0) {
            return 0;
        }
    } else {
        if(strlen(str) <= len && strncmp(str, filename, strlen(str)) == 0) {
            return 0;
        }
    }
    return 1;
}

int filename_same(const char *str, const char *exe) {
    int sexe = strlen(exe);
    int sstr = strlen(str);

    while(sexe >= 0 && sstr >= 0) {
        if(exe[sexe] != str[sstr]) {
            return 1;
        }
        sexe--;
        sstr--;
    }

    return 0;
}

int get_packages(Str *packages, size_t packages_size, int *count) {
    FILE *fp = popen("/bin/opkg list-installed", "r");
    if(fp == NULL) {
        return 1;
    }

    *count = 0;
    while(fgets(packages[*count].name, sizeof(packages[*count].name), fp) != NULL) {
        if(*count >= packages_size / sizeof(Str)) {
            return 1;
        }

        char *sep = strstr(packages[*count].name, " - ");
        if(sep == NULL) {
            continue;
        }
        packages[*count].len = sep - packages[*count].name;
        (*count)++;
    }

    pclose(fp);
    return 0;
}

int loop_dir(const char *path, loop_callback callback, void *data) {
    DIR *d;
    struct dirent *dire;
    d = opendir(path);
    if(d == NULL) {
        return 1;
    }
    int rc = 0;;
    while((dire = readdir(d)) != NULL) {
        if(strcmp(dire->d_name, ".") == 0 || strcmp(dire->d_name, "..") == 0) {
            continue;
        }

        if(callback(dire, data) != 0) {
            break;
        }
    }

    closedir(d);
    return 0;
}

typedef struct LoopInitsData {
    Str *inits;
    size_t inits_size;
    int *count;
} LoopInitsData;

static int get_init(struct dirent *dire, void *pdata) {
    LoopInitsData* data = (LoopInitsData*)pdata;
    int i = *data->count;
    memcpy(data->inits[i].name, dire->d_name, strlen(dire->d_name));
    data->inits[i].len = strlen(data->inits[i].name);
    (*data->count)++;
    return i >= data->inits_size / sizeof(char) ? 1 : 0;
}

int get_inits(Str *inits, size_t inits_size, int *count) {
    *count = 0;
    LoopInitsData data;
    data.inits = inits;
    data.inits_size = inits_size;
    data.count = count;
    return loop_dir("/etc/init.d", get_init, &data);
}

int str_cmp(const char *a, const Str *b) {
    return strlen(a) == b->len && strncmp(a, b->name, b->len) == 0 ? 0 : 1;
}

int str_in_list(const Str *strs, size_t strs_count, const char *str) {
    for(int i = 0; i < strs_count; i++) {
        if(str_cmp(str, &strs[i]) == 0) {
            return 0;
        }
    }
    return 1;
}

int dir_exists(const char *path) {
    DIR *dirc = opendir(path);
    if(dirc == NULL) {
        return 1;
    }
    
    closedir(dirc);
    return 0;
}