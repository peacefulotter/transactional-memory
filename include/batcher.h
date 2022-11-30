#pragma once

#include <pthread.h>
#include <string.h>

#include "tm.h"
#include "lock.h"

batcher* get_batcher();
size_t batcher_epoch(batcher* b);
void batcher_enter(batcher *b, struct transaction_t* tx);
bool batcher_leave(batcher *b, struct transaction_t* tx);
void batcher_wake_up(batcher* b);
void batcher_free(batcher *b);
void batcher_print(batcher* b);