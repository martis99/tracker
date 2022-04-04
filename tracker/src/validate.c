#include "validate.h"
#include "utils.h"

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_LINK_COUNT 512
#define MAX_LINK_BUSYBOX_COUNT 512
#define MAX_HASH_COUNT 1024

typedef struct LoopPathData {
    const char *path;
    char buf[MAX_PATH_LENGTH];
    char resolved[MAX_PATH_LENGTH];
    Link links[MAX_LINK_COUNT];
    int links_count;
    char links_busybox[MAX_LINK_BUSYBOX_COUNT * MAX_PATH_LENGTH];
    int links_busybox_count;
    Hash hashes[MAX_HASH_COUNT];
    int hashes_count;
    int rc;
} LoopPathData;

#include <errno.h>

static int loop_path(struct dirent *dire, void *pdata) {
    LoopPathData *data = (LoopPathData*)pdata;

    snprintf(data->buf, MAX_PATH_LENGTH, "%s%s", data->path, dire->d_name);

    memset(data->resolved, 0, sizeof(data->resolved));

    struct stat path_stat;
    stat(data->buf, &path_stat);
    if(S_ISDIR(path_stat.st_mode)) {
        return 0;
    }
    if(!(path_stat.st_mode & S_IXUSR)) {
        return 0;
    }

    if(strstr(data->buf, ".so") != NULL) {
        return 0;
    }

    if(realpath(data->buf, data->resolved) != NULL) {
        if(strcmp(data->resolved, data->buf) != 0) {
            if(strlen(data->resolved) >= MAX_PATH_LENGTH) {
                fprintf(stderr, "Path too long %s\n", data->resolved);
                data->rc = 1;
                return 1;
            }

            if(strcmp(data->resolved, "/bin/busybox") == 0) {
                if(data->links_busybox_count >= MAX_LINK_BUSYBOX_COUNT) {
                    fprintf(stderr, "Max busybox links count reached\n");
                    data->rc = 1;
                    return 1;
                }
                memcpy(&data->links_busybox[data->links_busybox_count++ * MAX_PATH_LENGTH], data->buf, MAX_PATH_LENGTH);
            } else {
                if(data->links_count >= MAX_LINK_COUNT) {
                    fprintf(stderr, "Max links count reached\n");
                    data->rc = 1;
                    return 1;
                }
                memcpy(data->links[data->links_count].path, data->buf, MAX_PATH_LENGTH);
                memcpy(data->links[data->links_count].exe, data->resolved, MAX_PATH_LENGTH);
                data->links_count++;
            }
            return 0;
        }
    }

    if(data->hashes_count >= MAX_HASH_COUNT) {
        fprintf(stderr, "Max haches count reached\n");
        data->rc = 1;
        return 1;
    }

    memcpy(data->hashes[data->hashes_count].exe, data->buf, MAX_PATH_LENGTH);
    hash_gen(data->buf, data->hashes[data->hashes_count].hash, MAX_HASH_LENGTH);
    data->hashes_count++;
    return 0;
}

void print_hashes() {
    LoopPathData data;
    data.rc = 0;
    data.links_busybox_count = 0;
    data.links_count = 0;
    data.hashes_count = 0;
    for(int i = 0; i < sizeof(s_paths) / sizeof(s_paths[0]); i++) {
        data.path = s_paths[i];
        printf("%s\n", data.path);
        loop_dir(data.path, loop_path, &data);
        if(data.rc != 0) {
            return;
        }
    }

printf("busy: %d\n", data.links_busybox_count);
    for(int i = 0; i < data.links_busybox_count; i++) {
        printf("\"%s\",\n", &data.links_busybox[i * MAX_PATH_LENGTH]);
    }

printf("links: %d\n", data.links_count);
    for(int i = 0; i < data.links_count; i++) {
        printf("{\"%s\", \"%s\"},\n", data.links[i].path, data.links[i].exe);
    }

    printf("hashes: %d\n", data.hashes_count);
    for(int i = 0; i < data.hashes_count; i++) {
        printf("{\"%s\", \"%s\"},\n", data.hashes[i].exe, data.hashes[i].hash);
    }
}

static void bin_to_strhex(const unsigned char *bin, unsigned int size, unsigned char *result) {
    unsigned char hex_str[]= "0123456789abcdef";
    for (unsigned int i = 0; i < size; i++) {
        result[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
        result[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }
    result[size * 2] = '\0';
}

int hash_gen(const char *path, unsigned char *hash, size_t size) {
    unsigned char buffer[4096];
    unsigned char digest[SHA_DIGEST_LENGTH];
    memset(hash, 0, size);

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if(fd == 0) {
        return 1;
    }
    size_t len;
    while((len = read(fd, buffer, sizeof(buffer) / sizeof(char))) > 0) {
        SHA1_Update(&ctx, buffer, len);
    }
    close(fd);

    if(SHA1_Final(digest, &ctx) == 0) {
        return 1;
    }

    bin_to_strhex(digest, sizeof(digest) / sizeof(unsigned char), hash);
    return 0;
}

int hash_validate(const char *exe, const char *hash) {
    for(int i = 0; i < sizeof(s_hashes) / sizeof(Hash); i++) {
        if(strcmp(exe, s_hashes[i].exe) == 0 && strcmp(hash, s_hashes[i].hash) == 0) {
            return 0;
        }
    }
    return 1;
}

int link_validate(const char *str, const char *exe) {
    if(strcmp(exe, "/bin/busybox") == 0) {
        for(int i = 0; i < sizeof(s_busybox) / sizeof(s_busybox[0]); i++) {
            if(strstr(s_busybox[i], str) != NULL) {
                return 0;
            }
        }
    } else {
        for(int i = 0; i < sizeof(s_links) / sizeof(Link); i++) {
            if(strstr(s_links[i].path, str) != NULL && strcmp(exe, s_links[i].exe) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

int cmd_validate(const char *cmd, const char *exe) {
    for(int i = 0; i < sizeof(s_comm_names) / sizeof(CommName); i++) {
        if(strcmp(s_cmd[i].cmd, cmd) == 0 && strcmp(exe, s_cmd[i].exe) == 0) {
            return 0;
        }
    }
    return 1;
}

int comm_validate(const char *comm, const char *exe) {
    for(int i = 0; i < sizeof(s_comm_names) / sizeof(CommName); i++) {
        if(strcmp(s_comm_names[i].comm, comm) == 0 && strcmp(exe, s_comm_names[i].exe) == 0) {
            return 0;
        }
    }
    return 1;
}

int socket_validate(const char *exe) {
    for(int i = 0; i < sizeof(s_socket) / sizeof(s_socket[0]); i++) {
        if(strcmp(s_socket[i], exe) == 0) {
            return 0;
        }
    }
    return 1;
}

static const char *s_get_filename(const char *str){
    const char *filename = strrchr(str, '/');
    return filename == NULL ? str : filename + 1; 
}

int exe_validate(const char *exe) {
    int len = s_get_filename(exe) - exe;
    for(int i = 0; i < sizeof(s_paths) / sizeof(s_paths[0]); i++) {
        const char *path = s_paths[i];
        if(strlen(path) == len && strncmp(path, exe, len) == 0) {
            return 0;
        }
    }
    return 1;
}

int package_validate(const char *exe) {
    for(int i = 0; i < sizeof(s_packages) / sizeof(s_packages[0]); i++) {
        if(strcmp(s_packages[i], exe) == 0) {
            return 0;
        }
    }
    return 1;
}

int cmd_change_validate(const char *a, const char *b) {
    for(int i = 0; i < sizeof(s_cmd_change) / sizeof(BinChange); i++) {
        if(strcmp(s_cmd_change[i].a, a) == 0 && strcmp(s_cmd_change[i].b, b) == 0) {
            return 0;
        }
    }
    return 1;
}

int comm_change_validate(const char *a, const char *b) {
    for(int i = 0; i < sizeof(s_comm_change) / sizeof(CommChange); i++) {
        if(strcmp(s_comm_change[i].a, a) == 0 && strcmp(s_comm_change[i].b, b) == 0) {
            return 0;
        }
    }
    return 1;
}

int exe_change_validate(const char *a, const char *b) {
    for(int i = 0; i < sizeof(s_exe_change) / sizeof(BinChange); i++) {
        if(strcmp(s_exe_change[i].a, a) == 0 && strcmp(s_exe_change[i].b, b) == 0) {
            return 0;
        }
    }
    return 1;
}
