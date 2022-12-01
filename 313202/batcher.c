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

    atomic_init(&b->blocked, 0);
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

bool wait_pred(batcher* b)
{
    return atomic_load(&(b->blocked));
}

void batcher_enter(batcher* b, transaction_t* tx)
{
    log_info("[%p]  batch_enter  blocked=%u", tx, b->blocked);
    if ( wait_pred(b) )
    {
        lock_acquire(b->block);
        while ( wait_pred(b) )
        {
            log_error("[%p]  batch_enter  WAITING", tx);
            lock_wait(b->block);
        }
        lock_release(b->block);
        log_error("[%p]  batch_enter  ENTERING", tx);
    }

    if ( tx->read_only)
    {
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
        log_info("[%p]  batch_enter  READ_ONLY");
    }

    lock_acquire(b->remaining_lock);
    b->remaining++;
    lock_release(b->remaining_lock);
    
    log_info("[%p]  batch_enter  - end, remaining=%zu", tx, b->remaining);
}

void batcher_allow_entry(batcher* b)
{
    log_info("[]  --- batcher_allow_entry");
    bool t = true;
    atomic_compare_exchange_strong(&(b->blocked), &t, false);
}

void batcher_block_entry(batcher* b)
{
    log_info("[]  --- batcher_block_entry");
    bool f = false;
    atomic_compare_exchange_strong(&(b->blocked), &f, true);
}

/**
 * @brief returns true if last tx to leave 
 */
bool batcher_leave(batcher* b, transaction_t* tx)
{
    log_info("[%p]  batch_leave  1", tx);

    if ( tx->read_only )
        batcher_block_entry(b);

    log_info("[%p]  batch_leave  2", tx);
    lock_acquire(b->remaining_lock);
    b->remaining--;
    bool last_remaining = b->remaining == 0;

    if ( !tx->read_only && last_remaining )
        batcher_block_entry(b);

    log_info("[%p]  batch_leave  3 remaining=%u", tx, b->remaining);
    lock_release(b->remaining_lock);

    log_info("[%p]  batch_leave  4 last=%u", tx, last_remaining);

    return last_remaining;
}

void batcher_wake_up(batcher* b)
{
    b->epoch++;
    log_error(" >>>>>>   batch_wake_up  epoch=%zu", b->epoch);
    log_error(" >>>>>>   batch_wake_up  epoch=%zu", b->epoch);
    log_error(" >>>>>>   batch_wake_up  epoch=%zu", b->epoch);
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