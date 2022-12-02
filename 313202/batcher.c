#include <stdlib.h>
#include <stdatomic.h>

#include "macros.h"
#include "batcher.h"
#include "lock.h"
#include "shared-lock.h"
#include "logger.h"
#include "tm.h"

batcher* get_batcher()
{
    batcher* b = malloc(sizeof(batcher)); 
    if ( unlikely( b == NULL ) ) 
        return NULL;

    b->blocked = 0;
    b->epoch = 0;
    b->remaining = 0;

    b->block = malloc(sizeof(struct lock_t));
    if (unlikely( !lock_init(b->block) ))
    {
        free(b);
        return NULL;
    }

    b->remaining_lock = malloc(sizeof(struct lock_t));
    if (unlikely( !lock_init(b->remaining_lock) ))
    {
        lock_cleanup(b->block);
        free(b);
        return NULL;
    }

    return b;
}

size_t batcher_epoch(batcher* batch)
{
    return batch->epoch;
}

void batcher_enter(batcher* b, transaction_t* tx)
{
    log_info("[%p]  batch_enter  blocked=%u", tx, b->blocked);
    lock_acquire(b->block);
    while ( b->blocked )
    {
        log_info("[%p]  batch_enter  WAITING", tx);
        lock_wait(b->block);
    }
    
    // lock_acquire(b->remaining_lock);
    b->remaining++;
    // lock_release(b->remaining_lock);
    lock_release(b->block);
    log_info("[%p]  batch_enter  ENTERING, remaining=%zu", tx, b->remaining);
}

void batcher_allow_entry(batcher* b)
{
    log_info("[]  --- batcher_allow_entry");
    b->blocked = false;
    lock_release(b->block);
}

/**
 * TODO - grader: modify policy
 * Policy: block on read_only finished
 *  OR last one to leave
 *  OR first tx to fail
 */
void batcher_block_entry(batcher* b)
{
    log_error("[]  -------- batcher_block_entry");
    b->blocked = true;
}

/**
 * @brief returns true if last tx to leave 
 */
bool batcher_leave(batcher* b, transaction_t* tx)
{
    lock_acquire(b->block);

    log_info("[%p]  batch_leave", tx);
    b->remaining--;
    bool last = b->remaining == 0;

    if ( tx->read_only || (!tx->read_only && last) )
        batcher_block_entry(b);

    log_info("[%p]  batch_leave  remaining=%u, last=%u", tx, b->remaining, last);

    return last;
}

void batcher_wake_up(batcher* b)
{
    b->epoch++;
    log_error(" >>>>>>   batch_wake_up  epoch=%zu", b->epoch);
    batcher_allow_entry(b);
    lock_wake_up(b->block);
}

void batcher_free(batcher* b)
{
    lock_cleanup(b->remaining_lock);
    lock_cleanup(b->block);
    free(b);
}

void batcher_print(batcher* b)
{
    log_info("epoch=%zu, remaining=%zu", b->epoch, atomic_load(&(b->remaining)));
}