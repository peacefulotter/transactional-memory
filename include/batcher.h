#include <pthread.h>
#include <string.h>

#include "lock.h"

#define MAX_BLOCKED 128

#ifndef PARSER_H
#define PARSER_H

typedef struct batcher batcher;

// FIXME vector instead of fixed size;

struct batcher
{
    size_t counter;
    size_t remaining;
    pthread_t *blocked;
    size_t nb_blocked;

    struct lock_t *lock;
};

batcher *get_batcher();
size_t batcher_epoch(batcher *batch);
void batcher_enter(batcher *b);
void batcher_leave(batcher *b);
void batcher_release(batcher *b);

#endif