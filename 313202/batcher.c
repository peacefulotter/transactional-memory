#include <stdlib.h>

#include "macros.h"
#include "batcher.h"
#include "lock.h"
#include "logger.h"
#include "tm.h"

batcher* get_batcher()
{
    batcher* b = malloc(sizeof(batcher)); 
    if ( unlikely( b == NULL ) ) return NULL;

    b->counter = 0;
    b->remaining = 0;
    b->nb_blocked = 0;

    b->round_lock = malloc(sizeof(struct lock_t));
    if ( unlikely( !lock_init(b->round_lock) ) )
    {
        free(b->round_lock);
        free(b);
        return NULL;
    }

    b->mutex = malloc(sizeof(struct lock_t));
    if ( unlikely( !lock_init(b->mutex) ) )
    {
        lock_cleanup(b->round_lock);
        free(b->round_lock);
        free(b);
        return NULL;
    }
    
    return b;
}

//TODO: why?
size_t batcher_epoch(batcher* batch)
{
    return batch->counter;
}

void batcher_enter(batcher* b, transaction_t* tx)
{
    lock_acquire(b->mutex);

    // TODO: per thread not per tx 

    bool first = b->remaining == 0;
    log_info("[%p]  batch_enter  first=%u", tx, first);
    if ( first )
        b->remaining = 1;
    else
    {
        b->nb_blocked++;
        size_t epoch = batcher_epoch(b);
        lock_release(b->mutex);
        lock_acquire(b->round_lock);
        while ( true )
        {
            lock_wait(b->round_lock);
            lock_acquire(b->mutex);
            if ( epoch != batcher_epoch(b) ) break;
            lock_release(b->mutex);
        }
        log_info("[%p]  batch_enter  ENTERING ", tx);
        lock_release(b->round_lock);
    }
    log_info("[%p]  batch_enter  - end  first=%u, thread=%zu", tx, first);
    
    lock_release(b->mutex);
}

/**
 * @brief returns true if last tx to leave 
 */
bool batcher_leave(batcher* b, transaction_t* tx)
{
    lock_acquire(b->mutex);
    bool last_remaining = b->remaining == 1;
    log_info("[%p]  batch_leave  remaining=%u", tx, b->remaining);
    lock_release(b->mutex);
    return last_remaining;
}

void batcher_wake_up(batcher* b)
{
    lock_acquire(b->mutex);
    log_info("          batch_leave  waking_up others");
    b->remaining = b->nb_blocked;
    b->nb_blocked = 0;
    b->counter++;
    lock_release(b->mutex);
    lock_wake_up(b->round_lock);
}

void batcher_free(batcher* b)
{
    lock_cleanup(b->round_lock);
    lock_cleanup(b->mutex);
    free(b);
}

void _batcher_print(batcher* b, transaction_t* tx)
{
    log_info("[%p] epoch=%zu, nb_blocked=%zu, remaining=%zu", tx, b->counter, b->nb_blocked, b->remaining);
}

void batcher_print(batcher* b)
{
    lock_acquire(b->mutex);
    _batcher_print(b, NULL);
    lock_release(b->mutex);
}