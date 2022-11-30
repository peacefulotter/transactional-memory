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

    b->first = true;
    b->counter = 0;
    b->remaining = 0;
    b->nb_blocked = 0;

    if (unlikely( !shared_lock_init(&(b->mutex)) ))
    {
        free(b);
        return NULL;
    }

    b->block = malloc(sizeof(struct lock_t));
    if (unlikely( !lock_init(b->block) ))
    {
        shared_lock_cleanup(&(b->mutex));
        free(b);
        return NULL;
    }

    b->remaining_lock = malloc(sizeof(struct lock_t));
    if (unlikely( !lock_init(b->remaining_lock) ))
    {
        shared_lock_cleanup(&(b->mutex));
        lock_cleanup(b->block);
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
    bool same = epoch == batcher_epoch(b);
    return same;
}

// TODO:  LAISSEZ ENTRER JUSQU'A FIN READ ONLY

void batcher_enter(batcher* b, transaction_t* tx)
{
    // 
    shared_lock_acquire_shared(&(b->mutex));
    // 

    bool t = true;
    bool first = atomic_compare_exchange_strong(&b->first, &t, false);
   
    log_info("[%p]  batch_enter  first=%u", tx, first);
    if ( !first )
    {
        size_t epoch = batcher_epoch(b);
        lock_acquire(b->block);
        while ( pred(b, tx, epoch) )
        {
            log_error("[%p]  batch_enter  WAITING on epoch=%zu", tx, epoch);
            lock_wait(b->block);
        }
        lock_release(b->block);
        log_error("[%p]  batch_enter  ENTERING prev=%zu, now=%zu", tx, epoch, batcher_epoch(b));
    }


    lock_acquire(b->remaining_lock);
    b->remaining++;
    lock_release(b->remaining_lock);
    
    log_info("[%p]  batch_enter  - end  first=%u, remaining=%zu", tx, first, b->remaining);
}

void batcher_final(batcher* b)
{
    shared_lock_release(&(b->mutex));
    shared_lock_release_shared(&(b->mutex));
}

/**
 * @brief returns true if last tx to leave 
 */
bool batcher_leave(batcher* b, transaction_t* tx)
{
    // -> false
    // log_info("[%p]  batch_leave  1 remaining=%u", tx, b->remaining);
    shared_lock_release_shared(&(b->mutex));
    // log_info("[%p]  batch_leave  2 remaining=%u", tx, b->remaining);
    shared_lock_acquire(&(b->mutex));
    // -> true

    // log_info("[%p]  batch_leave  3 remaining=%u", tx, b->remaining);
    lock_acquire(b->remaining_lock);
    b->remaining--;
    log_info("[%p]  batch_leave  4 remaining=%u", tx, b->remaining);
    bool last_remaining = b->remaining == 0;
    lock_release(b->remaining_lock);

    log_info("[%p]  batch_leave  5 remaining=%u, last=%u", tx, b->remaining, last_remaining);
    if ( !last_remaining )
        batcher_final(b);

    return last_remaining;
}

void batcher_wake_up(batcher* b)
{
    b->counter++;
    log_error(" >>>>>>   batch_leave  counter=%zu", b->counter);
    batcher_final(b);
    lock_wake_up(b->block);
}

void batcher_free(batcher* b)
{
    shared_lock_cleanup(&(b->mutex));
    lock_cleanup(b->block);
    free(b);
}

void batcher_print(batcher* b)
{
    log_info("epoch=%zu, nb_blocked=%zu, remaining=%zu", b->counter, b->nb_blocked, b->remaining);
}