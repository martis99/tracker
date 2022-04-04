#ifndef TRACKER_H
#define TRACKER_H

#include "utils.h"

typedef struct Tracker {
    Str packages[1024];
    int packages_count;
    Str inits[256];
    int inits_count;
} Tracker;

#endif