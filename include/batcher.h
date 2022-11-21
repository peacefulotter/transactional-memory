#include <pthread.h>
#include <string.h>

#include "lock.h"


#ifndef PARSER_H
#define PARSER_H

typedef struct batcher batcher;

struct batcher
{
    atomic_size_t counter;
    atomic_size_t remaining;

    pthread_t* blocked;

    struct lock_t *lock;
};

batcher* get_batcher();
size_t batcher_epoch(batcher *batch);
void batcher_enter(batcher *b);
bool batcher_leave(batcher *b);
void batcher_free(batcher *b);

#endif