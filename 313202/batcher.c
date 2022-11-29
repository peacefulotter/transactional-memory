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

bool pred(batcher* b, transaction_t* tx, size_t epoch)
{
    lock_acquire(b->mutex);
    bool same = epoch == batcher_epoch(b);
    lock_release(b->mutex);
    return same;
}

void batcher_enter(batcher* b, transaction_t* tx)
{
    // TODO: READ_WRITE LOCK = shared_lock
    lock_acquire(b->mutex);

    // TODO:  LAISSEZ ENTRER JUSQU'A FIN READ ONLY

    bool first = b->remaining == 0;
    log_info("[%p]  batch_enter  first=%u", tx, first);
    if ( !first )
    {
        size_t epoch = batcher_epoch(b);
        lock_release(b->mutex);
        lock_acquire(b->round_lock);
        while ( pred(b, tx, epoch) )
        {
            log_error("[%p]  batch_enter  WAITING on epoch=%zu", tx, epoch);
            lock_wait(b->round_lock);
        }
        lock_release(b->round_lock);
        lock_acquire(b->mutex);
        log_error("[%p]  batch_enter  ENTERING prev=%zu, now=%zu", tx, epoch, batcher_epoch(b));
    }
    
    b->remaining++;
    log_info("[%p]  batch_enter  - end  first=%u, remaining=%zu", tx, first, b->remaining);

    lock_release(b->mutex);
}

/**
 * @brief returns true if last tx to leave 
 */
bool batcher_leave(batcher* b, transaction_t* tx)
{
    log_info("[%p]  batch_leave  pre_leave remaining=%u", tx, b->remaining);
    lock_acquire(b->mutex);
    b->remaining--;
    bool last_remaining = b->remaining == 0;
    log_info("[%p]  batch_leave  remaining=%u, last=%u", tx, b->remaining, last_remaining);
    if ( !last_remaining )
        lock_release(b->mutex);
    return last_remaining;
}

void batcher_wake_up(batcher* b)
{
    b->counter++;
    log_error(" >>>>>>   batch_leave  counter=%zu", b->counter);
    lock_release(b->mutex);
    lock_wake_up(b->round_lock);
}

void batcher_free(batcher* b)
{
    lock_cleanup(b->round_lock);
    lock_cleanup(b->mutex);
    free(b);
}

void batcher_print(batcher* b)
{
    log_info("epoch=%zu, nb_blocked=%zu, remaining=%zu", b->counter, b->nb_blocked, b->remaining);
}